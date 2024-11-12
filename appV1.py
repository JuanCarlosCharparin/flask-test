'''

from flask import Flask, render_template

app = Flask(__name__)

#Ruta principal
@app.route('/')
def hello():
    #return "Hello, Flask desde mi pc"
    return render_template('hello.html')


#Ruta secundaria
@app.route('/info')
def info():
    #return "Esta pagina es de información"
    return render_template('info.html')

if __name__ == '__main__':
    app.run(debug=True)

'''


from flask import Flask, jsonify, request

app = Flask(__name__)

#usuarios simulando db

users = [
    {"id" : 1, "name" : "Juan", "lastName" : "Charparin", "age" : 24},
    {"id" : 2, "name" : "Esteban", "lastName" : "Maldonado", "age" : 31},
    {"id" : 3, "name" : "Daniel", "lastName" : "Fontana", "age" : 38}
]


#Ruta api get

@app.route('/api/users', methods=['GET'])
def get_users():
    return jsonify(users)


#Ruta api get id

@app.route('/api/users/<int:id>', methods=['GET'])
def get_users_id(id):
    user = next((u for u in users if u["id"] == id), None)
    if user is not None:
        return jsonify(user)
    return jsonify({"mensaje": "User not found"}), 404


#Ruta api post

@app.route('/api/users', methods=['POST'])
def post_users():
    new_user = request.get_json()
    new_user['id'] = len(users) + 1 #Generar nuevo id
    users.append(new_user)
    return jsonify(new_user), 201


#Ruta api update

@app.route('/api/users/<int:id>', methods=['PUT'])
def put_users(id):
    user = next((u for u in users if u["id"] == id), None)
    if user is None:
        return jsonify({"mensaje": "User not found"}), 404
    
    update_user = request.get_json()
    user.update(update_user)
    return jsonify(user)
    

if __name__ == '__main__':
    app.run(debug=True)