def test_s3_signed_url(s3_storage):
    url = s3_storage.generate_signed_url("test/file.txt")
    assert "X-Amz-Signature" in url
