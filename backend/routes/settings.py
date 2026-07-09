import json
import os
import shutil
import smtplib
import sqlite3
from email.mime.text import MIMEText
from datetime import datetime

from flask import Blueprint, request, jsonify, g, send_file
from app import get_db
from config import DATABASE_PATH
from routes.auth import login_required, admin_required
from routes.audit import audit_setting_change
from services.crypto_service import encrypt, decrypt

settings_bp = Blueprint('settings', __name__)


def _backups_dir() -> str:
    """备份目录：与数据库同级的 backups/ 目录。"""
    d = os.path.join(os.path.dirname(DATABASE_PATH), "backups")
    os.makedirs(d, exist_ok=True)
    return d


def _list_backups() -> list:
    d = _backups_dir()
    files = []
    for fn in os.listdir(d):
        if fn.endswith(".db"):
            fp = os.path.join(d, fn)
            files.append({
                "filename": fn,
                "size": os.path.getsize(fp),
                "created_at": datetime.fromtimestamp(os.path.getmtime(fp)).strftime("%Y-%m-%d %H:%M:%S"),
            })
    files.sort(key=lambda x: x["created_at"], reverse=True)
    return files

DEFAULT_ALERT_ON = json.dumps(["critical", "high"])


@settings_bp.route("/", methods=["GET"])
@settings_bp.route("", methods=["GET"])
@login_required
def settings_overview():
    """GET /api/settings — 返回配置概览"""
    db = get_db()
    _ensure_email_config(db)
    _ensure_email_rules(db)

    email_row = db.execute('SELECT enabled, host, port, from_addr, updated_at FROM email_config WHERE id = 1').fetchone()
    rules_row = db.execute('SELECT daily_digest, weekly_report FROM email_rules WHERE id = 1').fetchone()

    return jsonify({
        "email": {
            "enabled": bool(email_row["enabled"]) if email_row else False,
            "host": email_row["host"] or "" if email_row else "",
            "port": email_row["port"] if email_row else 587,
            "from_addr": email_row["from_addr"] or "" if email_row else "",
            "updated_at": email_row["updated_at"] or "" if email_row else "",
        },
        "rules": {
            "daily_digest": bool(rules_row["daily_digest"]) if rules_row else False,
            "weekly_report": bool(rules_row["weekly_report"]) if rules_row else False,
        },
    })


def _mask_password(password):
    """返回掩码后的密码: 有值返回 '****', 空返回 ''."""
    return '****' if password else ''


def _ensure_email_config(db):
    """确保 email_config 表存在且有一行数据 (id=1)。"""
    db.execute(
        '''CREATE TABLE IF NOT EXISTS email_config (
            id INTEGER PRIMARY KEY CHECK (id=1),
            enabled INTEGER DEFAULT 0,
            host TEXT DEFAULT '',
            port INTEGER DEFAULT 587,
            username TEXT DEFAULT '',
            password TEXT DEFAULT '',
            from_addr TEXT DEFAULT '',
            recipients TEXT DEFAULT '',
            alert_on TEXT DEFAULT '["critical","high"]',
            updated_at TEXT DEFAULT ''
        )'''
    )
    row = db.execute('SELECT id FROM email_config WHERE id = 1').fetchone()
    if not row:
        db.execute(
            '''INSERT OR IGNORE INTO email_config (id, enabled, host, port, username, password, from_addr, recipients, alert_on, updated_at)
               VALUES (1, 0, '', 587, '', '', '', '', ?, '')''',
            (DEFAULT_ALERT_ON,)
        )
    db.commit()


def _ensure_email_rules(db):
    """确保 email_rules 表存在。"""
    db.execute(
        '''CREATE TABLE IF NOT EXISTS email_rules (
            id INTEGER PRIMARY KEY CHECK (id=1),
            daily_digest INTEGER DEFAULT 0,
            weekly_report INTEGER DEFAULT 0,
            updated_at TEXT DEFAULT ''
        )'''
    )
    row = db.execute('SELECT id FROM email_rules WHERE id = 1').fetchone()
    if not row:
        db.execute(
            '''INSERT OR IGNORE INTO email_rules (id, daily_digest, weekly_report, updated_at)
               VALUES (1, 0, 0, '')'''
        )
    db.commit()


def _send_email(host, port, username, password, from_addr, recipients_str, subject, body):
    """通过 SMTP 发送邮件，返回 (success: bool, message: str)。"""
    recipients = [r.strip() for r in recipients_str.split(',') if r.strip()]
    if not recipients:
        return False, "收件人列表为空"

    msg = MIMEText(body, 'plain', 'utf-8')
    msg['Subject'] = subject
    msg['From'] = from_addr
    msg['To'] = ', '.join(recipients)

    try:
        if int(port) == 465:
            server = smtplib.SMTP_SSL(host, int(port), timeout=15)
        else:
            server = smtplib.SMTP(host, int(port), timeout=15)
            server.ehlo()
            server.starttls()
            server.ehlo()

        if username and password:
            server.login(username, password)

        server.sendmail(from_addr, recipients, msg.as_string())
        server.quit()
        return True, "测试邮件发送成功"
    except smtplib.SMTPAuthenticationError:
        return False, "SMTP 认证失败，请检查用户名和密码"
    except smtplib.SMTPConnectError:
        return False, f"无法连接到 SMTP 服务器 {host}:{port}"
    except smtplib.SMTPException as e:
        return False, f"SMTP 错误: {str(e)}"
    except Exception as e:
        return False, f"发送失败: {str(e)}"


# ---------------------------------------------------------------------------
# 1. GET /email-config
# ---------------------------------------------------------------------------
@settings_bp.route('/email-config', methods=['GET'])
@login_required
def get_email_config():
    db = get_db()
    _ensure_email_config(db)

    row = db.execute('SELECT * FROM email_config WHERE id = 1').fetchone()
    if not row:
        return jsonify({'error': '配置未初始化'}), 500

    return jsonify({
        'enabled': bool(row['enabled']),
        'host': row['host'] or '',
        'port': row['port'] or 587,
        'username': row['username'] or '',
        'password': _mask_password(row['password']),
        'from_addr': row['from_addr'] or '',
        'recipients': row['recipients'] or '',
        'alert_on': json.loads(row['alert_on'] or DEFAULT_ALERT_ON),
        'updated_at': row['updated_at'] or '',
    })


# ---------------------------------------------------------------------------
# 2. PUT /email-config
# ---------------------------------------------------------------------------
@settings_bp.route('/email-config', methods=['PUT'])
@admin_required
def update_email_config():
    db = get_db()
    _ensure_email_config(db)

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': '请求体必须为 JSON'}), 400

    existing = db.execute('SELECT * FROM email_config WHERE id = 1').fetchone()

    enabled = data.get('enabled', existing['enabled'] if existing else 0)
    host = data.get('host', existing['host'] if existing else '')
    port = data.get('port', existing['port'] if existing else 587)
    username = data.get('username', existing['username'] if existing else '')
    raw_password = data.get('password', existing['password'] if existing else '')
    # H-03 修复: 加密存储 SMTP 密码。前端传原始值 "****" 时保持旧密码不变
    if raw_password and raw_password != "****" and not raw_password.startswith("aes256:"):
        raw_password = encrypt(raw_password)
    elif raw_password == "****" and existing:
        raw_password = existing["password"]  # 保持旧值（前端未修改）
    from_addr = data.get('from_addr', existing['from_addr'] if existing else '')
    recipients = data.get('recipients', existing['recipients'] if existing else '')
    alert_on = data.get('alert_on', existing['alert_on'] if existing else DEFAULT_ALERT_ON)

    if isinstance(alert_on, list):
        alert_on = json.dumps(alert_on)

    now = sqlite3.datetime.datetime.now().isoformat() if hasattr(sqlite3, 'datetime') else __import__('datetime').datetime.now().isoformat()

    db.execute(
        '''INSERT OR REPLACE INTO email_config
           (id, enabled, host, port, username, password, from_addr, recipients, alert_on, updated_at)
           VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (int(enabled), host, int(port), username, raw_password, from_addr, recipients, alert_on, now)
    )
    db.commit()
    audit_setting_change(request.current_user_id, "email_config",
                         f"host={existing['host']}" if existing else "",
                         f"host={host}" if host else "")
    return jsonify({'message': '邮件配置已更新'})


# ---------------------------------------------------------------------------
# 3. POST /email-config/test
# ---------------------------------------------------------------------------
@settings_bp.route('/email-config/test', methods=['POST'])
@admin_required
def test_email_config():
    db = get_db()
    _ensure_email_config(db)

    row = db.execute('SELECT * FROM email_config WHERE id = 1').fetchone()
    if not row:
        return jsonify({'error': '邮件配置未初始化'}), 500

    if not row['enabled']:
        return jsonify({'message': '邮件通知未启用'})

    host = row['host']
    port = row['port']
    username = row['username']
    password = decrypt(row['password'])  # H-03 修复: 解密 SMTP 密码
    from_addr = row['from_addr']
    recipients = row['recipients']

    if not host or not recipients or not from_addr:
        return jsonify({'error': 'SMTP 配置不完整，请先填写服务器地址、发件人和收件人'}), 400

    success, msg = _send_email(
        host=host,
        port=port,
        username=username,
        password=password,
        from_addr=from_addr,
        recipients_str=recipients,
        subject='[Sentinel Security] 测试邮件',
        body='这是一封来自 Sentinel Security 平台的测试邮件。\n\n如果您收到此邮件，说明 SMTP 配置正确。',
    )

    if success:
        return jsonify({'message': msg})
    else:
        return jsonify({'error': msg}), 500


# ---------------------------------------------------------------------------
# 4. GET /alert-rules
# ---------------------------------------------------------------------------
@settings_bp.route('/alert-rules', methods=['GET'])
@login_required
def get_alert_rules():
    db = get_db()
    _ensure_email_config(db)
    _ensure_email_rules(db)

    config = db.execute('SELECT alert_on FROM email_config WHERE id = 1').fetchone()
    rules = db.execute('SELECT daily_digest, weekly_report FROM email_rules WHERE id = 1').fetchone()

    alert_on = json.loads(config['alert_on'] or DEFAULT_ALERT_ON) if config else json.loads(DEFAULT_ALERT_ON)

    return jsonify({
        'alert_on': alert_on,
        'daily_digest': bool(rules['daily_digest']) if rules else False,
        'weekly_report': bool(rules['weekly_report']) if rules else False,
    })


# ---------------------------------------------------------------------------
# 5. PUT /alert-rules
# ---------------------------------------------------------------------------
@settings_bp.route('/alert-rules', methods=['PUT'])
@admin_required
def update_alert_rules():
    db = get_db()
    _ensure_email_config(db)
    _ensure_email_rules(db)

    data = request.get_json(silent=True)
    if not data:
        return jsonify({'error': '请求体必须为 JSON'}), 400

    now = __import__('datetime').datetime.now().isoformat()

    # 更新 email_config 中的 alert_on
    if 'alert_on' in data:
        alert_on = data['alert_on']
        if isinstance(alert_on, list):
            valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
            alert_on = [s for s in alert_on if s in valid_severities]
            alert_on = json.dumps(alert_on)
        db.execute(
            'UPDATE email_config SET alert_on = ?, updated_at = ? WHERE id = 1',
            (alert_on, now)
        )

    # 更新 email_rules 中的 daily_digest / weekly_report
    existing = db.execute('SELECT * FROM email_rules WHERE id = 1').fetchone()
    daily_digest = int(data.get('daily_digest', existing['daily_digest'] if existing else 0))
    weekly_report = int(data.get('weekly_report', existing['weekly_report'] if existing else 0))

    db.execute(
        '''INSERT OR REPLACE INTO email_rules (id, daily_digest, weekly_report, updated_at)
           VALUES (1, ?, ?, ?)''',
        (daily_digest, weekly_report, now)
    )
    db.commit()
    audit_setting_change(request.current_user_id, "alert_rules",
                         f"alert_on={existing_alert_on}" if 'alert_on' in data else "",
                         f"alert_on={alert_on}" if 'alert_on' in data else "")
    return jsonify({'message': '告警规则已更新'})


# ---------------------------------------------------------------------------
# 6. 数据库备份 / 恢复
# ---------------------------------------------------------------------------
@settings_bp.route('/backups', methods=['GET'])
@login_required
@admin_required
def list_backups():
    """GET /api/settings/backups — 列出已有备份快照"""
    return jsonify({'backups': _list_backups(), 'current_db': os.path.basename(DATABASE_PATH)})


@settings_bp.route('/backup', methods=['POST'])
@login_required
@admin_required
def create_backup():
    """POST /api/settings/backup — 生成当前数据库的时间戳快照"""
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(_backups_dir(), f"sentinel-{ts}.db")
    try:
        shutil.copy2(DATABASE_PATH, dest)
    except Exception as e:
        return jsonify({'error': f'备份失败: {str(e)}'}), 500
    audit_setting_change(request.current_user_id, "db_backup", "", f"backup={os.path.basename(dest)}")
    return jsonify({'message': '备份已生成', 'filename': os.path.basename(dest),
                    'size': os.path.getsize(dest)})


@settings_bp.route('/backup/<filename>/download', methods=['GET'])
@login_required
@admin_required
def download_backup(filename: str):
    """GET /api/settings/backup/<filename>/download — 下载指定备份"""
    fp = os.path.join(_backups_dir(), os.path.basename(filename))
    if not os.path.isfile(fp):
        return jsonify({'error': '备份文件不存在'}), 404
    return send_file(fp, as_attachment=True, download_name=os.path.basename(fp))


@settings_bp.route('/restore', methods=['POST'])
@login_required
@admin_required
def restore_backup():
    """
    POST /api/settings/restore
      - 方式一（上传文件）：multipart/form-data, file=*.db
      - 方式二（从已有快照）：JSON {"filename": "sentinel-xxx.db"}
    恢复前自动对当前数据库做一次时间戳快照，便于回滚。
    """
    # 恢复前先备份当前库
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    safety = os.path.join(_backups_dir(), f"sentinel-pre-restore-{ts}.db")
    try:
        shutil.copy2(DATABASE_PATH, safety)
    except Exception as e:
        return jsonify({'error': f'恢复前自动备份失败: {str(e)}'}), 500

    src = None
    # 方式二：指定已有快照
    data = request.get_json(silent=True) or {}
    if data.get('filename'):
        cand = os.path.join(_backups_dir(), os.path.basename(data['filename']))
        if not os.path.isfile(cand):
            return jsonify({'error': '指定的备份文件不存在'}), 404
        src = cand
    else:
        # 方式一：上传文件
        f = request.files.get('file')
        if not f or not f.filename:
            return jsonify({'error': '请提供 file（上传的 .db）或 filename（已有快照）'}), 400
        if not f.filename.endswith('.db'):
            return jsonify({'error': '仅支持 .db 文件'}), 400
        tmp = os.path.join(_backups_dir(), f"upload-{ts}.db")
        f.save(tmp)
        src = tmp

    try:
        shutil.copy2(src, DATABASE_PATH)
    except Exception as e:
        return jsonify({'error': f'恢复失败: {str(e)}'}), 500
    finally:
        # 清理临时上传文件
        if src and src.endswith(f"upload-{ts}.db") and os.path.isfile(src):
            try:
                os.remove(src)
            except Exception:
                pass

    audit_setting_change(request.current_user_id, "db_restore", "",
                         f"restored_from={os.path.basename(src)}, safety={os.path.basename(safety)}")
    return jsonify({'message': '恢复成功，已自动备份恢复前状态', 'safety_backup': os.path.basename(safety)})


# ---------------------------------------------------------------------------
# 7. 系统外观：Logo 上传 / 读取 / 文件服务
# ---------------------------------------------------------------------------
def _uploads_dir() -> str:
    """上传目录：与数据库同级的 uploads/ 目录。"""
    d = os.path.join(os.path.dirname(DATABASE_PATH), "uploads")
    os.makedirs(d, exist_ok=True)
    return d


def _ensure_system_settings(db):
    """确保 key-value 系统配置表存在。"""
    db.execute(
        '''CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )'''
    )
    db.commit()


def _get_setting(db, key: str, default: str = '') -> str:
    _ensure_system_settings(db)
    row = db.execute('SELECT value FROM system_settings WHERE key = ?', (key,)).fetchone()
    return row['value'] if row else default


def _set_setting(db, key: str, value: str) -> None:
    _ensure_system_settings(db)
    db.execute('INSERT OR REPLACE INTO system_settings (key, value) VALUES (?, ?)', (key, value))
    db.commit()


ALLOWED_LOGO_EXT = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg'}


@settings_bp.route('/logo', methods=['GET'])
@login_required
def get_logo():
    """GET /api/settings/logo — 返回当前 Logo 的访问 URL（无则返回 null）"""
    db = get_db()
    logo_url = _get_setting(db, 'logo_url', '')
    return jsonify({'logo_url': logo_url or None})


@settings_bp.route('/registration', methods=['GET'])
@admin_required
def get_registration():
    """GET /api/settings/registration — 读取公开注册开关（仅管理员）"""
    db = get_db()
    return jsonify({'allow_public_register': _get_setting(db, 'allow_public_register', 'false') == 'true'})


@settings_bp.route('/registration', methods=['PUT'])
@admin_required
def set_registration():
    """PUT /api/settings/registration — 开启/关闭公开注册（仅管理员）"""
    data = request.get_json(silent=True) or {}
    allow = bool(data.get('allow_public_register', False))
    db = get_db()
    _set_setting(db, 'allow_public_register', 'true' if allow else 'false')
    db.commit()
    return jsonify({'allow_public_register': allow, 'message': '注册策略已更新'})


@settings_bp.route('/logo', methods=['POST'])
@login_required
@admin_required
def upload_logo():
    """POST /api/settings/logo — 管理员上传平台 Logo（png/jpg/jpeg/gif/webp/svg）"""
    db = get_db()
    f = request.files.get('file')
    if not f or not f.filename:
        return jsonify({'error': '请提供 file（图片文件）'}), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in ALLOWED_LOGO_EXT:
        return jsonify({'error': '仅支持 png/jpg/jpeg/gif/webp/svg 图片'}), 400

    # 删除旧 Logo 文件
    old = _get_setting(db, 'logo_url', '')
    if old and old.startswith('/api/settings/logo-file/'):
        try:
            os.remove(os.path.join(_uploads_dir(), os.path.basename(old)))
        except Exception:
            pass

    fn = f"logo{ext}"
    f.save(os.path.join(_uploads_dir(), fn))
    url = f"/api/settings/logo-file/{fn}"
    _set_setting(db, 'logo_url', url)
    audit_setting_change(request.current_user_id, "logo_upload", "", f"logo={fn}")
    return jsonify({'logo_url': url})


@settings_bp.route('/logo-file/<filename>', methods=['GET'])
def logo_file(filename: str):
    """GET /api/settings/logo-file/<filename> — 直接返回 Logo 图片（同域 <img> 可访问）"""
    fp = os.path.join(_uploads_dir(), os.path.basename(filename))
    if not os.path.isfile(fp):
        return jsonify({'error': 'logo 不存在'}), 404
    return send_file(fp)


@settings_bp.route('/logo', methods=['DELETE'])
@login_required
@admin_required
def remove_logo():
    """DELETE /api/settings/logo — 移除平台 Logo，恢复默认盾牌图标"""
    db = get_db()
    old = _get_setting(db, 'logo_url', '')
    if old and old.startswith('/api/settings/logo-file/'):
        try:
            os.remove(os.path.join(_uploads_dir(), os.path.basename(old)))
        except Exception:
            pass
    _set_setting(db, 'logo_url', '')
    audit_setting_change(request.current_user_id, "logo_remove", "", "")
    return jsonify({'message': 'logo 已移除'})
