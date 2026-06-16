from app.utils.auth import create_access_token, verify_token


def test_user_token_scope_verification():
    token = create_access_token("user-123", scope="user")
    assert verify_token(token.access_token, expected_scope="user") == "user-123"
    # verify wrong scope fails
    assert verify_token(token.access_token, expected_scope="session") is None


def test_session_token_scope_verification():
    token = create_access_token("sess-1", scope="session")
    assert verify_token(token.access_token, expected_scope="session") == "sess-1"
    assert verify_token(token.access_token, expected_scope="user") is None
