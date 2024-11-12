from flask import Flask, jsonify, request
import pyodbc
import jwt
from dotenv import load_dotenv
import os
import datetime
import bcrypt

# Cargar las variables de entorno desde el archivo .env
load_dotenv()
app = Flask(__name__)


# Obtener las cadenas de conexión de las variables de entorno en .env
connection_string1 = os.getenv("CONNECTION_STRING1")
connection_string2 = os.getenv("CONNECTION_STRING2")


SECRET_KEY = 'zaldivar20240311'
#TOKEN_EXPIRATION_MINUTES = 60


@app.route('/api/login', methods=['POST'])

def login():
 username = request.form.get('username')
 password = request.form.get('password')
 
   # Validar usuario y contrase�a
 usuario = Lee_Usuario(username)
 user_id = usuario [0]
 nombre = usuario[1]
 rol = usuario [3]
 pasw = usuario[2]

 # Verifica la contraseña ingresada
 if not bcrypt.checkpw(password.encode('utf-8'), pasw.encode('utf-8')):
    return jsonify({"status": "error", "message": "Contraseña incorrecta"}), 401

 privatekey = {
    "usuario_id": user_id,
    "nombre": nombre,
    "rol": rol,
    #"password": password,
    "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=60) 
 }
 print (privatekey)
 token = jwt.encode(privatekey, SECRET_KEY, algorithm='HS256')
 print(token)
 guardar_token(user_id, token)
 return (token)


@app.route('/api/newusers', methods=['POST'])

def register():
  new_user = request.get_json()

  # Verifica si los datos se están recibiendo correctamente
  if not new_user:
      return jsonify({"status": "error", "message": "Datos no recibidos o en formato incorrecto"}), 400 

  Insert_usuario(new_user['username'], new_user['password'], new_user['rol'], new_user['activo'])

  return jsonify({"status": "success", "message": "Usuario creado con éxito", "usuario nuevo": new_user}), 201


@app.route('/turnos/proximo/<historia_clinica>')
def get_proximo_turno(historia_clinica):
  # Conexi�n a la base de datos
  
  with pyodbc.connect(connection_string1) as connection:
    cursor = connection.cursor()

    # Consulta para obtener el turno
    sql = """
      SELECT top 1 t.fecha_turno, t.apellido_nombre, t.email, t.telefono
      FROM turnos_paciente t
      WHERE t.historia_clinica = ?
      AND t.estado = ?
    """
    cursor.execute(sql, [historia_clinica, 'X'])

    turno = cursor.fetchone()

  if not turno:
    return jsonify({'error': 'No se encontr� un turno pr�ximo para la historia cl�nica ' + historia_clinica}), 404

  # Enviar la respuesta
  return jsonify({'Fecha Turno': turno[0], 'Paciente': turno[1], 'Email': turno[2], 'Telefono': turno[3]}), 200


#@app.route('/paciente/<dni>')
def get_paciente(dni):

  with pyodbc.connect(connection_string1) as connection:
    cursor = connection.cursor()

    # Consulta para obtener los datos del paciente
    # Concatena codigos antes del numero  
    # Verifica si el numero esta compuesto por digitos
    sql = """
      SELECT apellido_nombre, email, 
        CASE 
          WHEN cel_part LIKE '%[^0-9+]%' THEN '-'
          ELSE CONCAT(cel_cod_pais, '', cel_cod_area, '', cel_part)
        END AS cel_part, 
        tel_part, Historia_Clinica
      FROM paciente
      WHERE nro_doc = ?;
    """
    cursor.execute(sql, [dni])

    paciente = cursor.fetchone()

  if not paciente:
    return jsonify({'error': 'No se encontr� un paciente con el DNI ' + dni}), 404

  # Enviar la respuesta
  return jsonify({'Historia_Clinica': paciente[4],'Apellido_Nombre': paciente[0], 'email': paciente[1], 'Celular': paciente[2],'telefono_Particular': paciente[3]}), 200



#@app.route('/pacientes/<dni>',)
@app.route('/pacientes/',)

def datos_paciente():
    dni = request.args.get("dni")
    token = request.args.get("token")
    usuario = request.args.get("usuario")

    try:
        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
     
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Token inv�lido'}), 401
    except jwt.InvalidSignatureError:
        return jsonify({'error': 'Token inv�lido'}), 401


    usuario_enc = decoded_token['nombre']
    if usuario == usuario_enc:
        return (get_paciente(dni)) 
    return jsonify({'Error': 'Usuario inv�lido'}), 401


def Lee_Usuario(username):

 with pyodbc.connect(connection_string2) as connection:
  cursor = connection.cursor()
  # Consulta para obtener el usuario
  sql = """
   SELECT id, username,password, rol
   FROM usuarios
   WHERE username = ?
  """
  cursor.execute(sql, [username])
  usuario = cursor.fetchone()
 return usuario


def guardar_token(U_id, token):
 
 with pyodbc.connect(connection_string2) as connection:
  cursor = connection.cursor()
  # Consulta para guardar el token
  sql = """
   INSERT INTO tokens (usuario_id, token)
   VALUES (?, ?)
  """
  cursor.execute(sql, [U_id, token])
  connection.commit()
  cursor.close()


def Insert_usuario (username, password, rol, activo):
  # Encriptado de la password
  encrypt_pass = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
  with pyodbc.connect(connection_string2) as connection:
    cursor = connection.cursor()
    #Consulta para insertar un nuevo usuario
    sql = """
    INSERT INTO usuarios (username, password, rol, activo)
        values(?, ?, ?, ?)
    """
    cursor.execute(sql, [username, encrypt_pass, rol, activo])
    connection.commit()
    cursor.close()


if __name__ == '__main__':
  #app.run(debug=True)
  app.run(host="0.0.0.0")







