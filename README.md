# Live Thermal Image-based CAPTCHA
CAPTCHAs serve as a protective measure to differentiate between humans and bots, preventing malicious bot programs from exploiting websites on the Internet. Most existing CAPTCHA solutions suffer from issues like subpar user experiences and disengagement. For example, Google's widely used image-based CAPTCHA service, known as reCAPTCHA v2, has issues of accessibility, usability, and security concerns. We aim to enhance the usability and accessibility of CAPTCHA-protected websites for all users without compromising security. We present a novel CAPTCHA system design based on real-time thermal images. Our design streamlines user interaction to a single click, capturing a thermal image of the user to automatically allow the CAPTCHA system to distinguish humans from bots by detecting human presence. During evaluation, our CAPTCHA system demonstrated an accuracy rate of 96.70\%. Furthermore, when operating on a low-powered server, our system achieved an average detection time of 73.60 milliseconds (ms) per thermal image.
Additionally, our system does not depend on users to complete typical AI tasks commonly employed within traditional CAPTCHA systems, such as tasks involving image selection and speech recognition. As a result, it provides theoretical immunity against potential AI-driven attacks. Our comprehensive analysis and usability assessment underscores the potential of the proposed thermal CAPTCHA to significantly enhance the effectiveness of traditional CAPTCHA systems while maintaining comparable or even superior levels of usability and security. 


## How can I run "Live-Thermal-Image-based-CAPTCHA" in any PC?

### Supported Environments
For tasks specific to web browsers, such as submitting a thermal image and receiving outcomes from the server’s object detector, we utilized Flask—a lightweight web framework developed in Python. Our image classifier network, _YOLOv4-tiny_, was implemented on top of Darknet—an open-source neural network framework coded in C and CUDA. This framework offers a rapid and uncomplicated setup and supports both CPU and GPU computations. We carried out our experiments in the environment of _Ubuntu 20.04_. To simulate a server with lower power consumption, the host machine—where the object detector operated—featured an _Intel Core i5-8550U (1.80 GHz) processor_, _8 GB of RAM_, and an _NVIDIA Geforce MX150 GPU_. The "***Application***" directory is the implementation part of our "**Live-Thermal-Image-based-CAPTCHA**."

### [(**Live-Thermal-Image-based-CAPTCHA**) running instruction](#ApplicationRunningInstruction):
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
>Anyone can run our Live-Thermal-Image-based-CAPTCHA in any OS. One only has to copy the ["***Application***"](https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA/tree/main/Application) directory and follow the running instructions mentioned ["How can I run "Live-Thermal-Image-based-CAPTCHA" in any PC"](https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA/tree/main#ApplicationRunningInstruction). If there is no error and the application still can't detect the thermal webcam, then try changing the "***camlist[\*]***" value in the "***app.py***" file. ***Usually, the value will be between (0-10)***.

>[!NOTE]
>If you face any problems to run the application, please email ```"**@gmail.com***"```
>Besides, anyone can change the database using the ["thermalCaptchaDatabase.py"](https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA/tree/main/Application) file, such as adding different website site-key or shared-key. The schema of our database is mentioned in the ["Database"](https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA/tree/main#DatabaseSchema) section.

## How can I generate my own weight with a thermal dataset?

The following instructions are for creating your custom weight:

1. Follow the [instruction](https://techzizou.com/yolo-installation-on-windows-and-linux/#install_linux) to create YOLOv4-darknet installation and usage on your system.(_For both Windows and Linux installation steps are mentioned in the blog._)
2. Clone the repository ```git clone https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA.git```.
3. Go to the "***Model_training***" directory ```cd Model_training```.
4. Create a folder name "***backup***" ```mkdir backup```.
5. Download the [dataset](https://drive.google.com/drive/folders/1kGLN7eINFEycZbP6KbQvJI4wv4C3aEfq?usp=sharing) folder and place it under the "***training***" directory. (_Make sure the folder name is "dataset". If downloaded with a different name, rename the folder to "dataset" and copy it._)
6. Inside the ```Live-Thermal-Image-based-CAPTCHA/Model_training/training/model_person_class``` folder, open the "***model_person.data***" file and ensure it's pointing to the right path.
   for me:
   ```
   classes = 1
   train  = /media/shovon/7CA47F71A47F2D302/CODE/darknet_testing/training/model_person_class/train.txt
   valid  = /media/shovon/7CA47F71A47F2D302/CODE/darknet_testing/training/model_person_class/test.txt
   names  = /media/shovon/7CA47F71A47F2D302/CODE/darknet_testing/training/model_person_class/model_person.names
   backup = /media/shovon/7CA47F71A47F2D302/CODE/darknet_testing/backup/
   ```
   example:
   ```
   classes = 1
   train  = /[your path]/training/model_person_class/train.txt
   valid  = /[your path]/training/model_person_class/test.txt
   names  = /[your path]/training/model_person_class/model_person.names
   backup = /[your path]/backup/
   ```
7. Inside the ```Live-Thermal-Image-based-CAPTCHA/Model_training/training/model_person_class``` folder, also open the "***train.txt***" and "***test.txt***" files and make sure it's pointing to the right path in the dataset folder.
   for me:
   ```
   /media/shovon/7CA47F71A47F2D301/CODE/darknet_testing/training/dataset/6_x_90.jpg
   /media/shovon/7CA47F71A47F2D301/CODE/darknet_testing/training/dataset/6_y_100.jpg
   /media/shovon/7CA47F71A47F2D301/CODE/darknet_testing/training/dataset/6_y_80.jpg
   /media/shovon/7CA47F71A47F2D301/CODE/darknet_testing/training/dataset/7_x_100.jpg
   ```
   example:
   ```
   /[your path]/training/dataset/6_x_90.jpg
   /[your path]/training/dataset/6_y_100.jpg
   /[your path]/training/dataset/6_y_80.jpg
   /[your path]/training/dataset/7_x_100.jpg
   ```
8. The entries in the "***train.txt***" and "***test.txt***" files also depend on the percentage of data you want for training and testing purposes. (***You can change the ratio***)
9. Inside the ```Live-Thermal-Image-based-CAPTCHA/Model_training/training/model_person_class``` folder open "***yolov4-tiny-model-person.cfg***" file. If you want to change the hyperparameters, please follow AlexeyAB [how to train 
 tiny yolo to detect your custom objects](https://github.com/AlexeyAB/darknet#how-to-train-to-detect-your-custom-objects). (_With the current configuration, we found the best result._)
10. Inside the "***Model_training***" directory, make a folder name "***weights***".
11. Download the pre trained model [weight](https://drive.google.com/file/d/1FGwnI2d9w10vri4e7R-V79b-dC4XJBhx/view?usp=drive_link) and place it under the "***weight***" folder.
12. Open the ```Makefile``` under ```Live-Thermal-Image-based-CAPTCHA/Model_training``` folder. Change the file depending on your GPU accessibility.

    For running on GPU:
    ```
    GPU=1
    CUDNN=1
    CUDNN_HALF=1
    OPENCV=1
    AVX=1
    OPENMP=1
    LIBSO=1
    ZED_CAMERA=0
    ZED_CAMERA_v2_8=0
    USE_CPP=0
    DEBUG=0

    ```
    Also, change ```ARCH= -gencode arch=compute_61,code=[sm_61,compute_61] ``` depending on your [GPU version](https://developer.nvidia.com/cuda-gpus). For more information, one can follow the [blog](https://www.myzhar.com/blog/tutorials/tutorial-nvidia-gpu-cuda-compute-capability/).

    For running on CPU:
    ```
    GPU=0
    CUDNN=0
    CUDNN_HALF=0
    OPENCV=1
    AVX=1
    OPENMP=1
    LIBSO=0
    ZED_CAMERA=0
    ZED_CAMERA_v2_8=0
    USE_CPP=0
    DEBUG=0
    ```
13. In the terminal, execute ```make```
14. In the terminal execute  ``` ./darknet detector train <path_to_your_.data_file> <path_to_your_.cfg_file> <path_to_your_pre-trained_weight> map```

    For me, the execution command was:
   ```./darknet detector train training/model_person_class/model_person.data training/model_person_class/yolov4-tiny-model-person.cfg weights/yolov4-tiny.conv.29 map```
15. Each time you change anything in the ***step[5-12]***, execute ```make clean``` in the terminal and re-execute the command mentioned in ***step[13,14]***.
16. After training, all the weights will be available in the ***backup*** ```Live-Thermal-Image-based-CAPTCHA/Model_training/training/model_person_class``` folder.

>[!IMPORTANT]
>We trained the model for **40,000 epochs**, resulting in an **average loss of 0.0509**. This score falls within the range of **0.5 to 0.03**, as indicated in the [YOLO documentation](https://github.com/AlexeyAB/darknet#how-to-train-to-detect-your-custom-objects) for an exemplary detector model.
>![chart](https://github.com/anonymouspaul96/Live-Thermal-Image-based-CAPTCHA/assets/142852373/a7620f85-82cc-4d8b-b9c3-6e5fd5c402b6)

## Generated weights comparison after every 10,000 iterations
You can check mAP for all the weights saved every **1000 iterations**, for example:- _yolov4-custom_10000.weights_, _yolov4-custom_20000.weights_, _yolov4-custom_30000.weights_, and so on. This lets you find out which weights file gives you the best result. The higher the **mAP**, the better it is. Please run the following command to check the **mAP** for a particular saved weights file where **xxxx** is its iteration number. (e.g.:- 4000, 5000, 6000,…)
```
!./darknet detector map <path_to_your_.data_file> <path_to_your_.cfg_file> <path_to_your_yolov4-custom_xxxx.weights> -points 0
```
For me, the command was:
```
!./darknet detector map ./training/model_person_class/model_person.data ./training/model_person_class/yolov4-tiny-model-person.cfg ./backup/yolov4-tiny-model-person_30000.weights -points 0
```
Weights | Detections count |  Unique truth count | Conf. threshold | TP | FP | FN | IoU threshold (\%) | Average IoU (\%) | mAP (\%) |
| :---         | :---         | :---         | :---         |     :---:      |     :---:      |     :---:      |          ---: |          ---: |     :---:      |
| [10,000](https://drive.google.com/file/d/1GrX1eikgRFOtfI0umJklOP82xV65yfq2/view?usp=sharing) | 1,286 | 745 | 0.25 | **722** | 257 | 23 | 50 | 59.14 | 80.8904 |
| [20,000](https://drive.google.com/file/d/1IfdSGWviVqmk1NNW_AhAPZ3bEpMQVYJd/view?usp=sharing) | 2,343 | 745 | 0.25 | 716 | 319 | **29** | 50 | 53.77 | 78.5271 |
| [**30,000**](https://drive.google.com/file/d/1DnBbmnqKM9lKUh9vZOPk4oxt4W3NzZaC/view?usp=sharing) | 2,756 | 745 | 0.25 | 715 | **212** | 30 | 50 | **61.51** | **83.5529** |
| [40,000](https://drive.google.com/file/d/1LBMGW-XTGu3RfBqBYozOCuDKV-CO5Ri7/view?usp=sharing) | 3,695 | 745 | 0.25 | 695 | 529 | 50 | 50 | 44.88 | 74.8232 |

## Google Form for Usability Study

Please fill out this [Google Form](https://docs.google.com/forms/d/e/1FAIpQLSdXhh1PwYUqI0w9QJ345XMYrjwgamNrBRx8WpyZLpWUhVk9eg/viewform) for the usability study. Thank you!

## Downloads
### Datasets
- [Original thermal image](https://drive.google.com/drive/folders/1RhkLUHs1So0swPK-_da2skrshN5og0Xz?usp=sharing)
- [Original & augmented thermal image](https://drive.google.com/drive/folders/1kGLN7eINFEycZbP6KbQvJI4wv4C3aEfq?usp=sharing)
- [Thermal images taken from their homes under typical living circumstances](https://drive.google.com/drive/folders/1XcNbx0LEm5WauFBxAKSlUsBKDElBAC7-?usp=sharing)
### Weights
- [yolov4-tiny-model-person_10000.weights](https://drive.google.com/file/d/1GrX1eikgRFOtfI0umJklOP82xV65yfq2/view?usp=sharing)
- [yolov4-tiny-model-person_20000.weights](https://drive.google.com/file/d/1IfdSGWviVqmk1NNW_AhAPZ3bEpMQVYJd/view?usp=sharing)
- [yolov4-tiny-model-person_30000.weights](https://drive.google.com/file/d/1DnBbmnqKM9lKUh9vZOPk4oxt4W3NzZaC/view?usp=sharing)
- [yolov4-tiny-model-person_40000.weights](https://drive.google.com/file/d/1LBMGW-XTGu3RfBqBYozOCuDKV-CO5Ri7/view?usp=sharing)

## [**Database Schema**](#DatabaseSchema):
### ServerVSWebsite Table
- **UniqueID**: INTEGER PRIMARY KEY AUTOINCREMENT
- **SiteKey**: TEXT UNIQUE NOT NULL
- **WebsiteName**: TEXT UNIQUE NOT NULL
- **SharedKey**: TEXT NOT NULL

### Users Table
- **UniqueID**: INTEGER PRIMARY KEY AUTOINCREMENT
- **SiteKey**: TEXT NOT NULL
- **WebsiteName**: TEXT NOT NULL
- **UserIPAddress**: TEXT NOT NULL
- **FOREIGN KEY (SiteKey)**: REFERENCES ServerVSWebsite(SiteKey)

### Detections Table
- **UniqueID**: INTEGER PRIMARY KEY AUTOINCREMENT
- **UserID**: INTEGER NOT NULL
- **Result**: INTEGER NOT NULL
- **Timestamp**: DATETIME DEFAULT CURRENT_TIMESTAMP
- **FOREIGN KEY (UserID)**: REFERENCES Users(UniqueID)

### UserNonce Table
- **UniqueID**: INTEGER PRIMARY KEY AUTOINCREMENT
- **UserID**: INTEGER NOT NULL
- **Nonce**: TEXT NOT NULL UNIQUE
- **Timestamp**: DATETIME DEFAULT CURRENT_TIMESTAMP
- **FOREIGN KEY (UserID)**: REFERENCES Users(UniqueID)

### TokenNonce Table
- **UniqueID**: INTEGER PRIMARY KEY AUTOINCREMENT
- **Token**: TEXT NOT NULL
- **Nonce**: TEXT NOT NULL UNIQUE
- **Timestamp**: DATETIME DEFAULT CURRENT_TIMESTAMP




