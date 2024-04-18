from config import IMAGE_SAVE_PATH
import cv2
import os

def capture_image(image_filename):
    """
    Captures an image from the webcam and saves it to a file.
    Args:
    image_filename (str): Filename to save the captured image.
    Returns:
    str: The path to the saved image file if successful, None otherwise.
    """
    # Ensure the directory exists
    os.makedirs(IMAGE_SAVE_PATH, exist_ok=True)
    full_path = os.path.join(IMAGE_SAVE_PATH, image_filename)

    # Start video capture
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Error: Cannot open webcam.")
        return None

    while True:
        ret, frame = cap.read()
        if not ret:
            print("Error: Cannot capture frame.")
            break

        # Display the frame and wait for key press
        cv2.imshow("Capture - Press 's' to save and exit, 'q' to quit", frame)
        key = cv2.waitKey(1) & 0xFF
        if key == ord('s'):
            cv2.imwrite(full_path, frame)
            print(f"Image saved to {full_path}")
            cap.release()
            cv2.destroyAllWindows()
            return full_path
        elif key == ord('q'):
            break

    cap.release()
    cv2.destroyAllWindows()
    return None
