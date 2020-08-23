# Install Ubuntu with python3
FROM python:3
# Set the working directory
WORKDIR /usr/src/app

# Copy and install all the requirements from requirements.txt
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy the rest of the files (app.py etc.)
COPY . . 

# Install the offline local pre-trained model
RUN pip install ./en_core_web_sm-2.3.1.tar.gz

# Run the command python app.py
CMD ["python", "app.py"]
