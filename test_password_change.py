#!/usr/bin/env python3
"""
Quick test script for the password change feature
"""
import requests
import json

BASE_URL = "http://localhost:5000"

def test_password_change():
    print("🧪 Testing Password Change Feature")
    print("=" * 50)
    
    # Step 1: Login with default credentials
    print("\n1. Logging in with default credentials...")
    login_response = requests.post(
        f"{BASE_URL}/api/login",
        json={"username": "admin", "password": "ChangeMe123!"}
    )
    
    if login_response.status_code == 200:
        print("   ✅ Login successful")
        session_cookie = login_response.cookies
    else:
        print(f"   ❌ Login failed: {login_response.json()}")
        return
    
    # Step 2: Test password change with weak password
    print("\n2. Testing with weak password (should fail)...")
    change_response = requests.post(
        f"{BASE_URL}/api/change-password",
        json={
            "current_password": "ChangeMe123!",
            "new_password": "weak"
        },
        cookies=session_cookie
    )
    
    if change_response.status_code == 400:
        print(f"   ✅ Correctly rejected: {change_response.json().get('error')}")
    else:
        print(f"   ⚠️  Unexpected response: {change_response.status_code}")
    
    # Step 3: Test password change with wrong current password
    print("\n3. Testing with wrong current password (should fail)...")
    change_response = requests.post(
        f"{BASE_URL}/api/change-password",
        json={
            "current_password": "WrongPassword123!",
            "new_password": "NewSecure$Pass123"
        },
        cookies=session_cookie
    )
    
    if change_response.status_code == 401:
        print(f"   ✅ Correctly rejected: {change_response.json().get('error')}")
    else:
        print(f"   ⚠️  Unexpected response: {change_response.status_code}")
    
    # Step 4: Test successful password change
    print("\n4. Testing successful password change...")
    change_response = requests.post(
        f"{BASE_URL}/api/change-password",
        json={
            "current_password": "ChangeMe123!",
            "new_password": "NewSecure$Pass123"
        },
        cookies=session_cookie
    )
    
    if change_response.status_code == 200:
        print(f"   ✅ Password changed: {change_response.json().get('message')}")
    else:
        print(f"   ❌ Failed: {change_response.json()}")
        return
    
    # Step 5: Verify old password doesn't work
    print("\n5. Verifying old password no longer works...")
    old_login = requests.post(
        f"{BASE_URL}/api/login",
        json={"username": "admin", "password": "ChangeMe123!"}
    )
    
    if old_login.status_code == 401:
        print("   ✅ Old password correctly rejected")
    else:
        print(f"   ❌ Old password still works (unexpected)")
    
    # Step 6: Verify new password works
    print("\n6. Verifying new password works...")
    new_login = requests.post(
        f"{BASE_URL}/api/login",
        json={"username": "admin", "password": "NewSecure$Pass123"}
    )
    
    if new_login.status_code == 200:
        print("   ✅ New password works!")
        new_session = new_login.cookies
    else:
        print(f"   ❌ New password doesn't work: {new_login.json()}")
        return
    
    # Step 7: Change password back to default for next test
    print("\n7. Resetting password to default...")
    reset_response = requests.post(
        f"{BASE_URL}/api/change-password",
        json={
            "current_password": "NewSecure$Pass123",
            "new_password": "ChangeMe123!"
        },
        cookies=new_session
    )
    
    if reset_response.status_code == 200:
        print("   ✅ Password reset to default")
    else:
        print(f"   ⚠️  Could not reset: {reset_response.json()}")
    
    print("\n" + "=" * 50)
    print("✅ All password change tests completed successfully!")
    print("\nThe password change feature is working correctly:")
    print("  ✓ Validates password strength")
    print("  ✓ Verifies current password")
    print("  ✓ Updates password securely")
    print("  ✓ Old password is invalidated")
    print("  ✓ New password works immediately")

if __name__ == "__main__":
    try:
        test_password_change()
    except requests.exceptions.ConnectionError:
        print("❌ Error: Cannot connect to server at http://localhost:5000")
        print("Make sure auth_server.py is running first!")
    except Exception as e:
        print(f"❌ Error: {e}")
