"""
通知模块 — 邮件告警、Webhook、企业微信等通知渠道
"""

from .email import EmailNotifier

__all__ = ["EmailNotifier"]
