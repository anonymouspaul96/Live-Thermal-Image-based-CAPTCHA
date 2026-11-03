from PIL import Image
import numpy as np
import cv2

def is_thermal_image(image):
    image_data = np.array(image)
    if len(image_data.shape) == 2:
        is_grayscale = True
        is_color = False
    elif len(image_data.shape) == 3 and image_data.shape[2] == 3:
        if np.all(image_data[:,:,0] == image_data[:,:,1]) and np.all(image_data[:,:,1] == image_data[:,:,2]):
            is_grayscale = True
            is_color = False
        else:
            is_grayscale = False
            is_color = True
    else:
        return "Unknown"
    if is_grayscale:
        return "Grayscale Image"
    if is_color:
        hsv_image = cv2.cvtColor(image_data, cv2.COLOR_RGB2HSV)
        hue, saturation, value = cv2.split(hsv_image)
        value_hist, _ = np.histogram(value, bins=256, range=(0, 256))
        high_value_pixels = np.sum(value > 200)
        if high_value_pixels > (image_data.shape[0] * image_data.shape[1] * 0.30):
            return "Thermal Image"
        else:
            return "Color Image"
    return "Unknown"