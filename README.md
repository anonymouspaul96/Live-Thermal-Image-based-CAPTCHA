The application directory is the implementation part of our "Live-Thermal-Image-based-CAPTCHA."

Running instruction:
1. Clone the repository.
2. Go to the "Application" directory.
3. Create a virtual environment.
4. Activate the environment.
5. Execute: "pip install -r requirements.txt"
6. Download the weight file from "https://drive.google.com/file/d/1DnBbmnqKM9lKUh9vZOPk4oxt4W3NzZaC/view?usp=sharing" and place it under the Application directory.
7. In the command line, execute: "flask run"

Note: If you can't detect the thermal webcam. Try changing the "camlist[*]" value in the app.py file. Usually, it will be between (0-10).
