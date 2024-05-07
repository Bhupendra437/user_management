# test_smtp_connection.py
import pytest
from unittest import mock
from app.utils.smtp_connection import SMTPClient

@pytest.fixture
def smtp_client():
    return SMTPClient(
        server='smtp.example.com',
        port=587,
        username='test@example.com',
        password='password'
    )

@mock.patch('smtplib.SMTP')
@mock.patch('app.utils.smtp_connection.logging')
def test_send_email_success(mock_logging, MockSMTP, smtp_client):
    # Create and configure a mock SMTP instance
    mock_smtp_instance = MockSMTP.return_value
    mock_smtp_instance.__enter__.return_value = mock_smtp_instance
    mock_smtp_instance.starttls = mock.Mock()
    mock_smtp_instance.login = mock.Mock()
    mock_smtp_instance.sendmail = mock.Mock()

    smtp_client.send_email(
        subject="Test Subject",
        html_content="<h1>Hello, World!</h1>",
        recipient="recipient@example.com"
    )

    # Verify that the expected methods were called
    mock_smtp_instance.starttls.assert_called_once()
    mock_smtp_instance.login.assert_called_once_with('test@example.com', 'password')
    mock_smtp_instance.sendmail.assert_called_once_with(
        'test@example.com',
        'recipient@example.com',
        mock.ANY  # Any MIME message string representation
    )
    mock_logging.info.assert_called_once_with("Email sent to recipient@example.com")

@mock.patch('smtplib.SMTP')
@mock.patch('app.utils.smtp_connection.logging')
def test_send_email_failure(mock_logging, MockSMTP, smtp_client):
    # Create and configure a mock SMTP instance
    mock_smtp_instance = MockSMTP.return_value
    mock_smtp_instance.__enter__.return_value = mock_smtp_instance
    mock_smtp_instance.starttls = mock.Mock()
    mock_smtp_instance.login = mock.Mock()
    mock_smtp_instance.sendmail = mock.Mock(side_effect=Exception("SMTP error"))

    with pytest.raises(Exception, match="SMTP error"):
        smtp_client.send_email(
            subject="Test Subject",
            html_content="<h1>Hello, World!</h1>",
            recipient="recipient@example.com"
        )

    mock_logging.error.assert_called_once_with("Failed to send email: SMTP error")
