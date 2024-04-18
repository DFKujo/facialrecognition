import cv2
import os
import logging
from config import current_config

IMAGE_SAVE_PATH = current_config.IMAGE_SAVE_PATH
# Set up logging
logging.basicConfig(level=logging.INFO)


def capture_image(image_filename):
    """
    Captures an image from the webcam and saves it to a file.
    """
    os.makedirs(IMAGE_SAVE_PATH, exist_ok=True)
    full_path = os.path.join(IMAGE_SAVE_PATH, image_filename)
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        logging.error("Cannot open webcam.")
        return None

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                logging.error("Cannot capture frame.")
                break

            cv2.imshow('Capture - Press \'s\' to save and exit, \'q\' to quit', frame)
            key = cv2.waitKey(1) & 0xFF
            if key == ord('s'):
                cv2.imwrite(full_path, frame)
                logging.info(f"Image saved to {full_path}")
                break
            elif key == ord('q'):
                logging.info("Image capture cancelled.")
                break
    except Exception as e:
        logging.error(f"An error occurred: {e}")
    finally:
        cap.release()
        cv2.destroyAllWindows()

    return None if key == ord('q') else full_path
