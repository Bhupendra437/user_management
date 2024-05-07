import asyncio
from uuid import uuid4
import pytest
from httpx import AsyncClient
from fastapi import status
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import AsyncMock, MagicMock, patch
from app.main import app
from app.schemas.user_schemas import UserCreate, UserResponse, UserUpdate, UserUpdateProf
from app.services.jwt_service import create_access_token
from app.services.user_service import UserService
from app.services.email_service import EmailService

# Create a test token for a predefined test user
test_token = create_access_token(data={"sub": "admin@example.com", "role": "ADMIN"})


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


@pytest.mark.asyncio
@patch("app.services.user_service.UserService.get_by_id", new_callable=AsyncMock)
async def test_get_user(mock_get_by_id, test_user):
    mock_get_by_id.return_value = test_user

    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.get(f"/users/{test_user.id}", headers={"Authorization": f"Bearer {test_user.access_token}"})
        assert response.status_code == 200
        assert response.json()["id"] == str(test_user.id)



@pytest.mark.asyncio
@patch("app.services.user_service.UserService.delete", new_callable=AsyncMock)
async def test_delete_user(mock_delete):
    mock_delete.return_value = True
    user_id = str(uuid4())
    async with AsyncClient(app=app, base_url="http://test") as ac:
        response = await ac.delete(f"/users/{user_id}", headers={"Authorization": f"Bearer {test_token}"})
        assert response.status_code == status.HTTP_204_NO_CONTENT
