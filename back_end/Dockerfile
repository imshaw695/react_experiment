# For more information, please refer to https://aka.ms/vscode-docker-python
FROM python:3.10

WORKDIR /var/www/
COPY ./requirements.txt /var/www/

# RUN mkdir ~/.sshRUN chmod 0700 ~/.ssh

RUN apt update
RUN apt-get update && apt-get install ffmpeg libsm6 libxext6  -y
RUN apt install -y libmariadb-dev-compat libmariadb-dev
RUN pip install -r requirements.txt

COPY . /var/www/

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV INSTANCE_TYPE=development
ENV GROUP_ID=1000
ENV USER_ID=1000
RUN useradd --user-group --system --create-home --no-log-init www --shell /bin/sh
USER www

# During debugging, this entry point will be overridden. For more information, please refer to https://aka.ms/vscode-docker-python-debug
# CMD ["python3", "-m" , "wsgi", "--reload"]
EXPOSE 5000
CMD [ "gunicorn", "-w", "3", "--bind", "0.0.0.0:5000", "wsgi:app", "--reload"]