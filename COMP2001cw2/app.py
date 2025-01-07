import datetime
import email
from decimal import Decimal
from flasgger import Swagger
import bcrypt
import pyodbc
import requests
from flask import Flask, jsonify, request
from functools import wraps

app = Flask(__name__)
app.config['SWAGGER'] = {
    'title': 'TrailService', # title of swagger page
    'uiversion': 3, # what version of swagger ui
    'securityDefinitions': {
        'basicAuth': {
            'type': 'basic', # authentication type
            'scheme': 'basic'
        }
    },
    'security': [{'basicAuth': []}]
}
Swagger(app)


# hash db passwords
def hash_password():
    conn = getdbconnection()
    cursor = conn.cursor()
    cursor.execute("SELECT email, password FROM uDetails")
    users = cursor.fetchall()
    for user in users:
        hashed_password = bcrypt.hashpw(user[1].encode('utf-8'), bcrypt.gensalt())
        cursor.execute("UPDATE uDetails SET password = ? WHERE email = ?", (hashed_password, user[0]))
    conn.commit()
    conn.close()


# authenticate the user
def authenticate_user(email, password):
    url = "https://web.socem.plymouth.ac.uk/COMP2001/auth/api/users"
    response = requests.post(url, json={"email": email, "password": password})
    print(f"Auth API Response: {response.status_code}, {response.text}")
    if response.status_code == 200:
        return response.json()
    return None


def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth = request.authorization
        if not auth or not auth.username or not auth.password:
            return jsonify({"error": "Authorisation header is missing or incomplete"}), 401

        # Validate user credentials against the database
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT userID, admin FROM uDetails WHERE email = ? AND password = ?",
            (auth.username, auth.password)
        )
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        # Add user details to the request context
        user_info = {"email": auth.username, "userID": user[0], "admin": bool(user[0])}
        return f(user=user_info, *args, **kwargs)

    return decorated_function


def require_role(role):
    def decorator(f):
        @wraps(f)
        def wrapper(user, *args, **kwargs):
            if role == 'admin' and not user['admin']:
                return jsonify({"error": "Access denied. Admin role required."}), 403
            return f(user=user, *args, **kwargs)

        return wrapper

    return decorator


# authentication test
@app.route('/protected', methods=['GET'])
@require_auth
def protected_route(user):
    return jsonify({"message": "This is a protected route"})


# get database connection
def getdbconnection():
    try:
        conn = pyodbc.connect(
            'DRIVER={ODBC Driver 17 for SQL Server};'
            'SERVER=DIST-6-505.uopnet.plymouth.ac.uk;'
            'DATABASE=COMP2001_WNichols;'
            'UID=WNichols;'
            'PWD=DgnY780+;'
        )
        return conn
    except Exception as e:
        print(f"Database connection failed: {e}")
        raise


def serialise_row(row, description):
    row_dict = dict(zip([column[0] for column in description], row))
    for key, value in row_dict.items():
        if isinstance(value, (datetime.datetime, datetime.date, datetime.time)):
            row_dict[key] = value.strftime('%Y-%m-%d %H:%M:%S')  # Adjust format as needed
        elif isinstance(value, Decimal):
            row_dict[key] = float(value)  # Convert decimals to floats
    return row_dict


# get all trails
@app.route('/api/trails', methods=['GET'])
@require_auth
def get_trails(user):
    """
    Retrieve all trails.
        ---
    tags:
      - Trails
    security:
      - basicAuth: []
    responses:
      200:
        description: A list of trails
        content:
          application/json:
            schema:
              type: array
              items:
                type: object
                properties:
                  trailID:
                    type: integer
                  name:
                    type: string
                  description:
                    type: string
                  elevationGain:
                    type: integer
                  estTime:
                    type: string
                    format: time
                  loop:
                    type: boolean
                  isPublic:
                    type: boolean
                  userID:
                    type: integer
      401:
        description: Unauthorised - Invalid credentials
      404:
        description: No trails found
      500:
        description: Internal server error
    """
    try:
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Trail")
        trails = cursor.fetchall()
        conn.close()

        if not trails:
            return jsonify({"message": "No trails found"}), 404

        # Serialise each row
        result = [serialise_row(row, cursor.description) for row in trails]

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# get an individual trail
@app.route('/api/Trail/<int:trailID>', methods=['GET'])
@require_auth
def get_trail(user, trailID):
    """
        Retrieve an individual trail by ID.
        ---
        tags:
          - Trails
        security:
          - basicAuth: []
        parameters:
          - name: trailID
            in: path
            required: true
            description: ID of the trail to retrieve
            schema:
              type: integer
        responses:
          200:
            description: The requested trail
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    trailID:
                      type: integer
                    name:
                      type: string
                    description:
                      type: string
                    elevationGain:
                      type: integer
                    estTime:
                      type: string
                      format: time
                    loop:
                      type: boolean
                    isPublic:
                      type: boolean
                    userID:
                      type: integer
          401:
            description: Unauthorised - Invalid credentials
          404:
            description: No trail found with the given ID
          500:
            description: Internal server error
        """
    try:
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Trail WHERE TrailID = ?", (trailID,))
        trail = cursor.fetchone()
        conn.close()

        if not trail:
            return jsonify({"error": "No trail found with the given ID"}), 404

        # Directly serialise the single row
        result = serialise_row(trail, cursor.description)

        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# create a new trail
@app.route('/api/trails', methods=['POST'])
@require_auth
def create_trail(user):
    """
    Create a new trail.
    ---
    tags:
        - Trails
    security:
        - basicAuth: []    # This indicates basic auth is required
    parameters:
        - name: body
          in: body
          required: true
          schema:
            type: object
            properties:
                name:
                    type: string
                    example: "Mountain Trail"
                description:
                    type: string
                    example: "A beautiful mountain trail"
                elevationGain:
                    type: integer
                    example: 500
                estTime:
                    type: string
                    example: "02:30"
                loop:
                    type: boolean
                    example: true
                isPublic:
                    type: boolean
                    example: true
            required:
                - name
                - description
    responses:
        201:
            description: Trail created successfully
        400:
            description: Bad request - Invalid input
        401:
            description: Unauthorised - Invalid credentials
        500:
            description: Internal server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid input"}), 400

        # Validate required fields
        if 'name' not in data or 'description' not in data:
            return jsonify({"error": "Name and description are required"}), 400

        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO Trail (name, description, elevationGain, estTime, loop, isPublic, userID)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["name"],
                data["description"],
                data.get("elevationGain", 0),  # default if not provided
                data.get("estTime", "00:00"),  # default if not provided
                data.get("loop", False),  # default if not provided
                data.get("isPublic", True),  # default if not provided
                user["userID"]
            )
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Trail created successfully"}), 201

    except KeyError as e:
        return jsonify({"error": f"Missing required field: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# update existing trail
@app.route('/api/Trail/<int:trailID>', methods=['PUT'])
@require_auth
@require_role('admin')
def update_trail(user, trailID):
    """
    Update an existing trail.
    ---
    tags:
        - Trails
    security:
        - basicAuth: []    # This indicates basic auth is required
    parameters:
        - name: trailID
          in: path
          required: true
          type: integer
          description: ID of the trail to update
        - name: body
          in: body
          required: true
          schema:
            type: object
            properties:
                name:
                    type: string
                    example: "Mountain Trail"
                description:
                    type: string
                    example: "A beautiful mountain trail"
                elevationGain:
                    type: integer
                    example: 500
                estTime:
                    type: string
                    example: "02:30"
                loop:
                    type: boolean
                    example: true
                isPublic:
                    type: boolean
                    example: true
            required:
                - name
                - description
    responses:
        200:
            description: Trail updated successfully
        400:
            description: Bad request - Invalid input
        401:
            description: Unauthorised - Invalid credentials
        404:
            description: Trail not found
        500:
            description: Internal server error
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid input"}), 400

        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE Trail SET name = ?, description = ?, elevationGain = ?, estTime = ?, loop = ?, isPublic = ? "
            "WHERE TrailID = ?",
            (
                data["name"],
                data["description"],
                data["elevationGain"],
                data["estTime"],
                data["loop"],
                data["isPublic"],
                trailID,
            ),
        )
        conn.commit()
        conn.close()
        return jsonify({"message": "Trail updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# delete a trail
@app.route('/api/Trail/<int:trailID>', methods=['DELETE'])
@require_auth
@require_role('admin')
def delete_trail(user, trailID):
    """
        Delete a trail.
        ---
        tags:
          - Trails
        security:
          - basicAuth: []
        parameters:
          - name: trailID
            in: path
            required: true
            description: ID of the trail to delete
            schema:
              type: integer
        responses:
          200:
            description: Trail deleted successfully
          401:
            description: Unauthorised - Invalid credentials
          403:
            description: Access denied - Admin role required
          500:
            description: Internal server error
        """
    try:
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Location WHERE trailID = ?", (trailID,))
        cursor.execute("DELETE FROM Trail WHERE TrailID = ?", (trailID,))
        conn.commit()
        conn.close()
        return jsonify({"message": "Trail deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# create location for trail
@app.route('/api/Trail/<int:trailID>/locations', methods=['POST'])
@require_auth
def create_trail_location(user, trailID):
    """
    Create a new location for a trail.
    ---
    tags:
        - Locations
    security:
        - basicAuth: []
    parameters:
        - name: trailID
          in: path
          required: true
          type: integer
          description: ID of the trail to add location to
        - name: body
          in: body
          required: true
          schema:
            type: object
            properties:
                longitude:
                    type: number
                    format: float
                    example: -122.4194
                latitude:
                    type: number
                    format: float
                    example: 37.7749
                trailOrder:
                    type: integer
                    example: 1
            required:
                - longitude
                - latitude
                - trailOrder
    responses:
        201:
            description: Location created successfully
        400:
            description: Bad request - Invalid input
        401:
            description: Unauthorised - Invalid credentials
        500:
            description: Internal server error
    """
    try:
        data = request.get_json()
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO Location (trailID, longitude, latitude, trailOrder)"
                       " VALUES (?, ?, ?, ?)",
                       (trailID, data['longitude'], data['latitude'], data['trailOrder'],))
        conn.commit()
        conn.close()
        return jsonify({"message": "Location created successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# get locations for a trail
@app.route('/api/Trail/<int:trailID>/locations', methods=['GET'])
@require_auth
def get_trail_locations(user, trailID):
    """
        Retrieve all locations for a specific trail.
        ---
        tags:
          - Locations
        security:
          - basicAuth: []
        parameters:
          - name: trailID
            in: path
            required: true
            description: ID of the trail for which locations are being retrieved.
            schema:
              type: integer
        responses:
          200:
            description: List of locations for the specified trail.
          401:
            description: Unauthorized - Invalid credentials.
          404:
            description: No locations found for the given trail.
          500:
            description: Internal server error.
    """
    try:
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM Location WHERE trailID = ?", (trailID,))
        locations = cursor.fetchall()
        conn.close()

        if not locations:
            return jsonify({"message": "No locations found for the given trail"}), 404

        return jsonify([serialise_row(row, cursor.description) for row in locations])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# update a location
@app.route('/api/Trail/<int:trailID>/locations/<int:locationID>', methods=['PUT'])
@require_auth
def update_trail_location(user, trailID, locationID):
    """
    Update a location within a trail.
    ---
    tags:
        - Locations
    security:
        - basicAuth: []
    parameters:
        - name: trailID
          in: path
          required: true
          schema:
            type: integer
          description: ID of the trail containing the location
        - name: locationID
          in: path
          required: true
          schema:
            type: integer
          description: ID of the location to update
        - in: body
          name: body
          required: true
          schema:
            type: object
            required:
              - longitude
              - latitude
              - trailOrder
            properties:
              longitude:
                type: number
                format: float
                example: -122.4194
              latitude:
                type: number
                format: float
                example: 37.7749
              trailOrder:
                type: integer
                example: 1
    responses:
        200:
          description: Location updated successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        400:
          description: Bad request - Invalid input
        401:
          description: Unauthorised - Invalid credentials
        500:
          description: Internal server error
    """
    try:
        data = request.get_json()
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("UPDATE Location SET longitude = ?, latitude = ?, trailOrder = ?"
                       " WHERE trailID = ? AND LocationID = ?",
                       (data['longitude'], data['latitude'], data['trailOrder'], trailID, locationID))
        conn.commit()
        conn.close()
        return jsonify({"message": "Location updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# delete a location
@app.route('/api/Trail/<int:trailID>/locations/<int:locationID>', methods=['DELETE'])
@require_auth
@require_role('admin')
def delete_trail_location(user, trailID, locationID):
    """
    Delete a location from a trail.
    ---
    tags:
        - Locations
    security:
        - basicAuth: []
    parameters:
        - name: trailID
          in: path
          required: true
          type: integer
          description: ID of the trail containing the location
        - name: locationID
          in: path
          required: true
          type: integer
          description: ID of the location to delete
    responses:
        200:
            description: Location deleted successfully
        401:
            description: Unauthorised - Invalid credentials
        403:
            description: Access denied - Admin role required
        500:
            description: Internal server error
    """
    try:
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM Location WHERE trailID = ? AND LocationID = ?", (trailID, locationID))
        conn.commit()
        conn.close()
        return jsonify({"message": "Location deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# create a feature
@app.route('/api/Trail/<int:trailID>/features', methods=['POST'])
@require_auth
def create_trail_feature(trailID):
    """
    Create a new feature for a trail.
    ---
    tags:
        - Features # categories endpoint under features in swagger
    security:
        - basicAuth: [] #indicates authentication method
    parameters: # list of parameters and their data types
        - name: trailID
          in: path
          required: true
          type: integer
          description: ID of the trail to add feature to
        - name: body
          in: body
          required: true
          schema:
            type: object # expects json object
            properties:
                featureID:
                    type: integer
                feature:
                    type: string
            required: # specifies which fields are mandatory
                - featureID
                - feature
    responses:
        201:
            description: Feature created successfully # code for success
        400:
            description: Bad request - Invalid input # error for invalid input
        401:
            description: Unauthorised - Invalid credentials # error for invalid credentials
        500:
            description: Internal server error # http status code for internal server error
    """
    try:
        data = request.get_json() #extract json data
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO trailFeatures (featureID, trailID, feature) VALUES (?, ?, ?)", # SQL to insert new features
                       (data['featureID'],
                        trailID,
                        data['feature']))
        conn.commit()
        conn.close()
        return jsonify({"message": "Feature created successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# retrieve features
@app.route('/api/Trail/<int:trailID>/features', methods=['GET'])
@require_auth
def get_trail_features(trailID):
    """
        Retrieve all features for a specific trail.
        ---
        tags:
          - Features
        security:
          - basicAuth: []
        parameters:
          - name: trailID
            in: path
            required: true
            description: ID of the trail for which features are being retrieved
            schema:
              type: integer
        responses:
          200:
            description: List of features for the specified trail
            content:
              application/json:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      featureID:
                        type: integer
                      trailID:
                        type: integer
                      feature:
                        type: string
          401:
            description: Unauthorised - Invalid credentials
          404:
            description: No features found for the given trail
          500:
            description: Internal server error
        """
    try:
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM trailFeatures WHERE trailID = ?", (trailID,))
        features = cursor.fetchall()
        conn.close()

        if not features:
            return jsonify({"message": "No features found for the given trail"}), 404

        return jsonify([serialise_row(row, cursor.description) for row in features])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# update a feature
@app.route('/api/Trail/<int:trailID>/features/<int:featureID>', methods=['PUT'])
@require_auth
def update_trail_feature(user, trailID, featureID):
    """
    Update a feature for a trail.
    ---
    tags:
        - Features
    security:
        - basicAuth: []
    parameters:
        - name: trailID
          in: path
          required: true
          schema:
            type: integer
          description: ID of the trail containing the feature
        - name: featureID
          in: path
          required: true
          schema:
            type: integer
          description: ID of the feature to update
        - in: body
          name: body
          required: true
          schema:
            type: object
            required:
              - feature
            properties:
              feature:
                type: string
    responses:
        200:
          description: Feature updated successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  message:
                    type: string
        400:
          description: Bad request - Invalid input
        401:
          description: Unauthorised - Invalid credentials
        500:
          description: Internal server error
    """
    try:
        data = request.get_json()
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("UPDATE trailFeatures SET feature = ? WHERE trailID = ? AND featureID = ?",
                       (data['feature'], trailID, featureID))
        conn.commit()
        conn.close()
        return jsonify({"message": "Feature updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# delete a feature
@app.route('/api/Trail/<int:trailID>/features/<int:featureID>', methods=['DELETE'])
@require_auth
@require_role('admin')
def delete_trail_feature(user, trailID, featureID):
    """
    Delete a feature from a trail.
    ---
    tags:
        - Features
    security:
        - basicAuth: []
    parameters:
        - name: trailID
          in: path
          required: true
          type: integer
          description: ID of the trail containing the feature
        - name: featureID
          in: path
          required: true
          type: integer
          description: ID of the feature to delete
    responses:
        200:
            description: Feature deleted successfully
        401:
            description: Unauthorised - Invalid credentials
        403:
            description: Access denied - Admin role required
        500:
            description: Internal server error
    """
    try:
        conn = getdbconnection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM trailFeatures WHERE trailID = ? AND featureID = ?", (trailID, featureID))
        conn.commit()
        conn.close()
        return jsonify({"message": "Feature deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)