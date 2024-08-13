# CollabSphere
An Influencer Engagement and Sponsorship Coordination Platform

## Getting Started
To run CollabSphere locally on your machine, follow these steps:

1. Create a virtual environment to isolate project dependencies:
   ```
   python -m venv venv
   ```
   
2. Activate the virtual environment (on Windows):
   ```
   venv/Scripts/activate
   ```

3. Install the project dependencies using pip:
   ```
   pip install -r requirements.txt
   ```
4. Update environemt variables (.env file):
    ```
    FLASK_DEBUG=true
    FLASK_APP=app.py
    SECRET_KEY=your_secret_key_here
    SQL_ALCHEMY_DATABASE_URI=sqlite:///db_name.sqlite3
    SQLALCHEMY_TRACK_MODIFICATIONS=true
    ```

5. Start the Flask development server:
   ```
   flask run
   ```
6. Access the CollabSphere web application by opening a web browser and navigating to `http://localhost:5000`.

