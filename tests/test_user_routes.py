import asyncio
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import status
from uuid import uuid4
from app.main import app  # Ensure correct import of your FastAPI instance
from app.services.user_service import UserService
from app.services.email_service import EmailService
from app.services.jwt_service import create_access_token

# Ensure mock_get_current_user is correctly imported or defined
# from app.tests.mocks import mock_get_current_user

# Create a test token for a predefined test user
test_token = create_access_token(data={"sub": "testuser@example.com", "role": "ADMIN"})

@pytest.fixture(scope="function")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
async def test_user(db_session: AsyncSession, email_service: EmailService):
    user_data = {
        "email": "test@example.com",
        "password": "securePassword123!",
        "first_name": "Test",
        "last_name": "User",
        "nickname": "testuser",
        "role": "ADMIN"
    }
    user = await UserService.create(db_session, user_data, email_service)
    if user:
        user.access_token = create_access_token(data={"sub": user.email, "role": str(user.role.name)})
    return user

@pytest.mark.asyncio
async def test_get_user_success(test_user):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get(f"/users/{test_user.id}", headers={"Authorization": f"Bearer {test_user.access_token}"})
        assert response.status_code == status.HTTP_200_OK
        assert response.json()['id'] == str(test_user.id)
