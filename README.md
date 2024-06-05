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
    **Content:** "Site registered successfully"

- **Error Responses**

  - **Code:** 400 BAD REQUEST
    **Content:** "Site already exists"

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error registering site"


## User Registration

Registers a new user with its associated username and password.

- **URL**

  `/api/register`

- **Method**

  `POST`

- **Data Params**

  | Parameter | Type   | Description              |
  |-----------|--------|--------------------------|
  | `username`| string | User's username          |
  | `password`| string | User's password          |

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


## Site Login

Authenticates a site and generates a JWT token.

- **URL**

  `/api/site/login`

- **Method**

  `POST`

- **Data Params**

  | Parameter | Type   | Description                |
  |-----------|--------|----------------------------|
  | `site`    | string | Site's name                |
  | `password`| string | Site's password            |

- **Success Response**

  - **Code:** 200 OK
    **Content:** JSON object with JWT token:
    ```json
    {
      "token": "JWT_TOKEN"
    }
    ```

- **Error Responses**

  - **Code:** 400 BAD REQUEST
    **Content:** "Invalid site or password"

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error logging in"


## Secure Access

Authenticates a site and grants access based on the provided session token. (This conatins the site codes so you should use it in the backend)

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
    **Content:** "Invalid site, password, or session token"

  - **Code:** 403 FORBIDDEN
    **Content:** "Access denied. Invalid token."

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error logging in"


## Write JSON Data

Writes data for a specific website to a JSON file. (suitable to be used on the client)

- **URL**

  `/api/writeJson`

- **Method**

  `POST`

- **Data Params**

  | Parameter     | Type   | Description                     |
  |---------------|--------|---------------------------------|
  | `sessiontoken`| string | Session token received from user|
  | `website`     | string | Name of the website             |
  | `data`        | object | Data to be written to JSON file |

- **Success Response**

  - **Code:** 200 OK
    **Content:** "Data written to USERNAME.json under WEBSITE successfully"

- **Error Responses**

  - **Code:** 403 FORBIDDEN
    **Content:** "Access denied. Invalid token."

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error writing to JSON file"


## Read JSON Data

Reads data for a specific website from a JSON file.(suitable to be used on the client)

- **URL**

  `/api/readJson`

- **Method**

  `POST`

- **Data Params**

  | Parameter     | Type   | Description                     |
  |---------------|--------|---------------------------------|
  | `sessiontoken`| string | Session token received from user|
  | `website`     | string | Name of the website             |

- **Success Response**

  - **Code:** 200 OK
    **Content:** JSON object with website data

- **Error Responses**

  - **Code:** 404 NOT FOUND
    **Content:** "Website data not found"

  - **Code:** 403 FORBIDDEN
    **Content:** "Access denied. Invalid token."

  - **Code:** 500 INTERNAL SERVER ERROR
    **Content:** "Error reading JSON file"


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

2. User Registration:

   ```http
   POST /api/register
   Content-Type: application/json

   {
     "username": "USERNAME",
     "password": "USERPASSWORD"
   }
   ```

3. User Login:

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

4. Site Login:

   ```http
   POST /api/site/login
   Content-Type: application/json

   {
     "site": "SITENAME",
     "password": "PASSWORDOFYOURCHOICE"
   }
   ```

   Response will contain a JWT token.

5. Secure Access:

   ```http
   POST /api/site/secureaccess
   Content-Type: application/json

   {
     "site": "SITENAME",
     "password": "PASSWORDOFYOURCHOICE",
     "sessiontoken": "SESSION_TOKEN_HASH"
   }
   ```

   Response will contain the username

.

6. Write JSON Data:

   ```http
   POST /api/writeJson
   Content-Type: application/json

   {
     "sessiontoken": "SESSION_TOKEN_HASH",
     "website": "WEBSITE",
     "data": { "key": "value" }
   }
   ```

7. Read JSON Data:

   ```http
   POST /api/readJson
   Content-Type: application/json

   {
     "sessiontoken": "SESSION_TOKEN_HASH",
     "website": "WEBSITE"
   }
   ```