print("On line 1 in wsgi")
# Application entry point.
from website import create_app
print("On line 3 in wsgi")
app = create_app()
print("On line 6 in wsgi")
print(f'__name__ is {__name__}')

if __name__ == "__main__":
    print("On line 9 in wsgi")
    app.run(host='0.0.0.0', debug=True)
    print("On line 11 in wsgi")