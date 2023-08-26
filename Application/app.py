from flask import Flask, render_template, request, jsonify
from PIL import Image
import sys
import numpy as np
import cv2
from yolo_detection_images import runModel
from PIL import Image
import pygame
import pygame.camera
import time
import io
import os

# img = os.path.join('static', 'Image')

app = Flask(__name__)

# Responsible for capturing image using webcam


def capture():
    # initializing  the camera
    pygame.camera.init()

    # make the list of all available cameras
    camlist = pygame.camera.list_cameras()

    # if camera is detected or not
    if camlist:

        # initializing the cam variable with default camera
        # if it doesn't detect any webcam change the value camlist[*]. Normally it will be between (0-10).
        cam = pygame.camera.Camera(camlist[0], (640, 480))

        # opening the camera
        cam.start()

        # capturing the single image
        image = cam.get_image()

        # saving the image
        pygame.image.save(image, "thermalImage.jpg") #you can directly send the image to the server withouth saving in the drive. you just have to retrun the image instead of saving it in th drive. 
        cam.stop()

    # if camera is not detected the moving to else part
    else:
        print("No camera on current device")


############################################## THE REAL DEAL ###############################################

# after clicking the "button" in the index.html it will be routed tho this function.
@app.route('/shell', methods=["GET", "POST"])
def run_script():
    if request.method == "POST":
        capture()
        #time.sleep(0.5) # Not needed, Used checking robustness 
        img = cv2.imread('./thermalImage.jpg', -1)
        # receiving img(image with bounaady box), foundLabel(detected lable from image), conf(confidence on detection)
        img, foundLabel, conf = runModel(img) #sending the image to the model for detction. No need for capturing the detection image. I wanted to show the detection result in the browser.
        # cv2.imshow('After sending image to browser', img)
        # cv2.waitKey(0)
        cv2.imwrite(
            '/media/shovon/7CA47F71A47F2D302/CODE/Ubuntu-CODE/Professor-son/Object-Detection-YOLO/static/Image/detection.jpg', img) # change directory address accordingly.
        return render_template("show.html", label=foundLabel, conf=conf)
    return render_template("index.html")


# Didn't use in the final system.
@app.route('/test', methods=['GET', 'POST'])
def test():
    print("log: got at test", file=sys.stderr)
    return jsonify({'status': 'succces'})

# By default it will load index.html


@app.route('/')
def home():
    return render_template('./index.html')


@app.after_request
def after_request(response):
    print("log: setting cors", file=sys.stderr)
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers',
                         'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE')
    return response


# for debugging "python3 app.py"
if __name__ == '__main__':
    app.run(debug=True)
