# tests/test_email_service.py
import pytest
from unittest.mock import AsyncMock, Mock, patch
from app.services.email_service import EmailService
from app.models.user_model import User

@pytest.fixture
def smtp_client_mock():
    return Mock()

@pytest.fixture
def template_manager_mock():
    template = Mock()
    template.render_template = Mock(return_value="<html>Mock Content</html>")
    return template

@pytest.fixture
def email_service(smtp_client_mock, template_manager_mock):
    email_service = EmailService(template_manager_mock)
    email_service.smtp_client = smtp_client_mock
    return email_service

@pytest.fixture
def user():
    return User(
        id="user-123",
        first_name="John",
        last_name="Doe",
        email="john.doe@example.com",
        verification_token="token-abc"
    )

@pytest.mark.asyncio
async def test_send_user_email_valid(email_service, smtp_client_mock, template_manager_mock):
    user_data = {
        "name": "John Doe",
        "email": "john.doe@example.com",
        "verification_url": "http://example.com/verify"
    }
    email_type = "email_verification"

    await email_service.send_user_email(user_data, email_type)

    template_manager_mock.render_template.assert_called_once_with(
        "email_verification", **user_data
    )
    smtp_client_mock.send_email.assert_called_once_with(
        "Verify Your Account", "<html>Mock Content</html>", "john.doe@example.com"
    )

@pytest.mark.asyncio
async def test_send_user_email_invalid_type(email_service):
    with pytest.raises(ValueError, match="Invalid email type"):
        await email_service.send_user_email({"name": "John Doe", "email": "john.doe@example.com"}, "invalid_type")

@pytest.mark.asyncio
@patch("settings.config.settings.server_base_url", "http://example.com/")
async def test_send_verification_email(email_service, user, smtp_client_mock, template_manager_mock):
    verification_url = f"http://example.com/verify-email/{user.id}/{user.verification_token}"

    await email_service.send_verification_email(user)

    template_manager_mock.render_template.assert_called_once_with(
        "email_verification", name=user.first_name, verification_url=verification_url, email=user.email
    )
    smtp_client_mock.send_email.assert_called_once_with(
        "Verify Your Account", "<html>Mock Content</html>", user.email
    )

@pytest.mark.asyncio
async def test_send_professional_status_email(email_service, user, smtp_client_mock, template_manager_mock):
    await email_service.send_professional_status_email(user)

    template_manager_mock.render_template.assert_called_once_with(
        "professional_status", name=user.first_name, email=user.email
    )
    smtp_client_mock.send_email.assert_called_once_with(
        "Congratulations! You've become a professional user.",
        "<html>Mock Content</html>",
        user.email
    )
