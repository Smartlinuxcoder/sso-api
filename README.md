# API Documentation

## Register Site

Registers a new site with its associated password.

- **URL**

  `/api/site/register`

- **Method**

  `POST`

- **Data Params**

  | Parameter | Type   | Description              |
  |-----------|--------|--------------------------|
  | `site`    | string | Name of the site         |
  | `password`| string | Password for the site    |

- **Success Response**

  - **Code:** 201 CREATED
    **Content:** "User registered successfully"

- **Error Responses**

  - **Code:** 400 BAD REQUEST
    **Content:** "Username already exists"

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error registering user"


## User Login

Authenticates a user and generates a session token.

- **URL**

  `/api/login`

- **Method**

  `POST`

- **Data Params**

  | Parameter | Type   | Description                |
  |-----------|--------|----------------------------|
  | `username`| string | User's username            |
  | `password`| string | User's password            |
  | `site`    | string | Name of the site           |

- **Success Response**

  - **Code:** 200 OK
    **Content:** JSON object with session token:
    ```json
    {
      "hash": "SESSION_TOKEN_HASH"
    }
    ```

- **Error Responses**

  - **Code:** 400 BAD REQUEST
    **Content:** "Invalid username or password"

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error logging in"


## Secure Access

Authenticates a site and grants access based on the provided session token.

- **URL**

  `/api/site/secureaccess`

- **Method**

  `POST`

- **Data Params**

  | Parameter     | Type   | Description                     |
  |---------------|--------|---------------------------------|
  | `site`        | string | Name of the site                |
  | `password`    | string | Password for the site           |
  | `sessiontoken`| string | Session token received from user|

- **Success Response**

  - **Code:** 200 OK
    **Content:** JSON object with username:
    ```json
    {
      "username": "USER_NAME"
    }
    ```

- **Error Responses**

  - **Code:** 400 BAD REQUEST
    **Content:** "Invalid username or password"

  - **Code:** 403 FORBIDDEN
    **Content:** "Access denied. Invalid token."

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error logging in"


## Example Usage

1. Register a new site:

   ```http
   POST /api/site/register
   Content-Type: application/json

   {
     "site": "SITENAME",
     "password": "PASSWORDOFYOURCHOICE"
   }
   ```

2. User Login:

   ```http
   POST /api/login
   Content-Type: application/json

   {
     "username": "USERNAME",
     "password": "USERPASSWORD",
     "site": "SITENAME"
   }
   ```

   Response will contain a session token.

3. Secure Access:

   ```http
   POST /api/site/secureaccess
   Content-Type: application/json

   {
     "site": "SITENAME",
     "password": "PASSWORDOFYOURCHOICE",
     "sessiontoken": "SESSION_TOKEN_HASH"
   }
   ```

   Response will contain the username.

Thanks to AdrianoTech for playing the italian anthem in vc.