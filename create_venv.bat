rem I have a development folder set up at the top of c: drive 
rem then have a folder called python versions inside that 
rem download python into the folder like so..- DO NOT ADD TO PATH
rem ..\python_versions\3_10\
rem navigate to the top level of your repo and type

rem ..\python_versions\3_11\python -m venv venv

call venv\Scripts\activate.bat

rem If you can see (base) after (venv) in the terminal window, type conda deactivate.

pip install -r back_end\requirements.txt

rem vscode recogmises the venv and offers to make it default for that repo