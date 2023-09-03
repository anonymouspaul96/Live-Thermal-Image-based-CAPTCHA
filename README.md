# Live Thermal Image-based CAPTCHA
CAPTCHAs serve as a protective measure to differentiate between humans and bots, preventing malicious bot programs from exploiting websites on the Internet. The majority of existing CAPTCHA solutions suffer from issues like subpar user experiences and disengagement. Our aim is to enhance the usability and accessibility of CAPTCHA-protected websites for all users. This paper presents a novel CAPTCHA system design based on real-time live thermal images. Our design streamlines user interaction to a single click for granting access to the thermal web camera, allowing the CAPTCHA system to automatically discern humans from bots by detecting the presence of humans. Specifically, we utilized the YOLOv4-tiny (You Only Look Once) algorithm to detect humans in live thermal images, achieving a 96.70% accuracy rate in our evaluation. Furthermore, when operating on a low-powered server, our system attained an average detection time of 73.60 milliseconds per thermal image. Additionally, our system does not depend on users to complete typical AI tasks commonly employed within traditional CAPTCHA systems, such as tasks involving image selection and speech recognition. As a result, it provides theoretical immunity against potential AI-driven attacks. Our comprehensive analysis and usability assessment underscores the potential of the proposed thermal CAPTCHA to significantly enhance the effectiveness of traditional CAPTCHA systems while maintaining comparable or even superior levels of usability.


## How can I run "Live-Thermal-Image-based-CAPTCHA" in any PC?

### Supported Environments
For tasks specific to web browsers, such as submitting a thermal image and receiving outcomes from the server’s object detector, we utilized Flask—a lightweight web framework developed in Python. Our image classifier network, _YOLOv4-tiny_, was implemented on top of Darknet—an open-source neural network framework coded in C and CUDA. This framework not only offers rapid and uncomplicated setup but also supports both CPU and GPU computations. We carried out our experiments in the environment of _Ubuntu 20.04_. To simulate a server with lower power consumption, the host machine—where the object detector operated—featured an I_ntel Core i5-8550U (1.80 GHz) processor_, _8 GB of RAM_, and an _NVIDIA Geforce MX150 GPU_. The "***Application***" directory is the implementation part of our "**Live-Thermal-Image-based-CAPTCHA**."

### (**Live-Thermal-Image-based-CAPTCHA**) running instruction:
1. Clone the repository ```git clone https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA.git```
2. In the terminal
   ```
   cd Live-Thermal-Image-based-CAPTCHA
   cd Application
   ```
5. Create a virtual environment ```python3 -m venv venv```
6. Activate the environment ```source venv/bin/activate```
7. Execute: ```pip install -r requirements.txt```
8. Download the [weight](https://drive.google.com/file/d/1DnBbmnqKM9lKUh9vZOPk4oxt4W3NzZaC/view?usp=sharing) file and place it under the "***Application***" directory.
9. In the command line, execute: ```flask run```
10. Click the ```Click to pass the CAPTCHA``` button.
    ![homepage](https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA/assets/142852373/fcb842e6-e8a3-45e5-a585-eb5b301e7357)
12. The result of "**Live-Thermal-Image-based-CAPTCHA**" after a person is detected.
    ![afterVerification](https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA/assets/142852373/ea2b134f-f13d-43a7-9a5d-b551a0f65211)

>[!WARNING]
>If you get an error like ``` ln = [ln[i[0] - 1] for i in net.getUnconnectedOutLayers()] IndexError: invalid index to scalar variable.``` Then please remove the bracket with 0: ```ln = [ln[i - 1] for i in net.getUnconnectedOutLayers()]```, line 50 in yolo_detection_images.py file.

>[!IMPORTANT]
>Anyone can run our Live-Thermal-Image-based-CAPTCHA in any OS. One only has to copy the "***Application***" directory and follow the running instructions. If there is no error and the application still can't detect the thermal webcam, then try changing the "***camlist[\*]***" value in the "***app.py***" file. ***Usually, the value will be between (0-10)***.

>[!NOTE]
>If you face any problems to run the application, please email "***ap.anonymouspaul@gmail.com***"

The following instructions are for creating your custom weight for your model:

1. Follow the "https://techzizou.com/yolo-installation-on-windows-and-linux/#install_linux" instruction to create YOLOv4-darknet installation and usage on your system.
2. Clone the repository.
3. Go to the "Model_training" directory.
4. Download the "dataset" folder from "https://drive.google.com/drive/folders/1kGLN7eINFEycZbP6KbQvJI4wv4C3aEfq?usp=sharing" and place it under the "training" directory.
5. Inside the "Model_training" directory, make a folder name "weights".
6. Download the "yolov4-tiny.weights" from "https://drive.google.com/file/d/1iUYvf24txvvt8JZU3pXTLl3prZeF6YON/view?usp=sharing" and place it under the "weight" folder.
