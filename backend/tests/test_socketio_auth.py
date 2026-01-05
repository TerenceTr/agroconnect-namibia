def test_refresh_token_required():
    from backend.socketio.namespaces import _auth_user
    assert _auth_user(None) is None
    assert _auth_user({"refresh_token": "invalid"}) is None
