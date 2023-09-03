## How can I run "Live-Thermal-Image-based-CAPTCHA" in any PC?
The application directory is the implementation part of our "Live-Thermal-Image-based-CAPTCHA."

(Live-Thermal-Image-based-CAPTCHA) running instruction:
1. Clone the repository ```git clone https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA.git```
2. In the terminal
   ```
   cd Live-Thermal-Image-based-CAPTCHA
   cd Application
   ```
5. Create a virtual environment ```python3 -m venv venv```
6. Activate the environment ```source venv/bin/activate```
7. Execute: ```pip install -r requirements.txt```
8. Download the [weight](https://drive.google.com/file/d/1DnBbmnqKM9lKUh9vZOPk4oxt4W3NzZaC/view?usp=sharing) file and place it under the "Application" directory.
9. In the command line, execute: ```flask run```

>[!NOTE]
>Anyone can run our Live-Thermal-Image-based-CAPTCHA in any OS. One only has to copy the "Application" directory and follow the running instructions. If you can't detect the thermal webcam. Try changing the "camlist[*]" value in the "app.py" file. Usually, the value will be between (0-10).
>
>If you get an error like "ln = [ln[i[0] - 1] for i in net.getUnconnectedOutLayers()] IndexError: invalid index to scalar variable." Then please modify "remove the bracket with 0: ln = [ln[i - 1] for i in net.getUnconnectedOutLayers()]", line 50 in yolo_detection_images.py file.

The following instructions are for creating your custom weight for your model:

1. Follow the "https://techzizou.com/yolo-installation-on-windows-and-linux/#install_linux" instruction to create YOLOv4-darknet installation and usage on your system.
2. Clone the repository.
3. Go to the "Model_training" directory.
4. Download the "dataset" folder from "https://drive.google.com/drive/folders/1kGLN7eINFEycZbP6KbQvJI4wv4C3aEfq?usp=sharing" and place it under the "training" directory.
5. Inside the "Model_training" directory, make a folder name "weights".
6. Download the "yolov4-tiny.weights" from "https://drive.google.com/file/d/1iUYvf24txvvt8JZU3pXTLl3prZeF6YON/view?usp=sharing" and place it under the "weight" folder.
