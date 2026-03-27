from app import app

client = app.test_client()
try:
    response = client.get("/")
    print("Status:", response.status_code)
    print("Data length:", len(response.data))
except Exception as e:
    import traceback
    traceback.print_exc()
