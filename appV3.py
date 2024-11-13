from flask import Flask, jsonify, request, render_template, redirect, url_for, flash, session
import pyodbc
import jwt
from dotenv import load_dotenv
import os
import datetime
import pytz
import bcrypt

# Cargar las variables de entorno desde el archivo .env
load_dotenv()
app = Flask(__name__)


# Obtener las cadenas de conexión de las variables de entorno en .env
connection_string1 = os.getenv("CONNECTION_STRING1")
connection_string2 = os.getenv("CONNECTION_STRING2")


app.secret_key = 'zaldivar20240311'
#TOKEN_EXPIRATION_MINUTES = 60

# configuramos zona horaria local con pytz
local_time = pytz.timezone('America/Argentina/Buenos_Aires')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Validar usuario y contraseña
        usuario = Lee_Usuario(username)
        
        if not usuario:
            flash("Usuario no encontrado", "danger")
            return render_template('login.html')
        
        user_id = usuario[0]
        nombre = usuario[1]
        pasw = usuario[2]
        rol = usuario[3]

        # Verifica la contraseña ingresada
        if not bcrypt.checkpw(password.encode('utf-8'), pasw.encode('utf-8')):
            flash("Contraseña incorrecta", "danger")
            return render_template('login.html')
        
        # Calcula fechas
        fecha_creacion = datetime.datetime.now(local_time)
        fecha_expiracion = fecha_creacion + datetime.timedelta(minutes=60)

        # Generar token JWT (si es necesario)
        privatekey = {
            "usuario_id": user_id,
            "nombre": nombre,
            "rol": rol,
            "exp": fecha_expiracion
        }
        token = jwt.encode(privatekey, app.secret_key, algorithm='HS256')
        guardar_token(user_id, token, fecha_creacion, fecha_expiracion)

        # Guarda el usuario en la sesión
        session['usuario'] = {
            "user_id": user_id,
            "nombre": nombre,
            "rol": rol
        }
        
        flash("Inicio de sesión exitoso", "success")
        # Redirige a una página de inicio o panel de control
        return redirect(url_for('dashboard'))

    # Si es un GET, simplemente renderiza el formulario de inicio de sesión
    return render_template('login.html')

#registro de nuevo usuario
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        new_user = request.form
        # Verifica si los datos se están recibiendo correctamente
        if not new_user:
            flash("Datos no recibidos o en formato incorrecto", "danger")
            return render_template('register.html')
        
        activo = 1 if new_user.get('activo', False) == 'on' else 0

        # Inserta el usuario en la base de datos
        Insert_usuario(new_user['username'], new_user['password'], new_user['rol'], activo)

        flash("Usuario creado con éxito", "success")
        return redirect(url_for('login'))
    
    # Si es un GET, simplemente renderiza el formulario de registro
    return render_template('register.html')

#pagina principal posterior alogin
@app.route('/dashboard')
def dashboard():
    usuario = session.get('usuario')
    return render_template('dashboard.html', usuario=usuario)



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
        decoded_token = jwt.decode(token, app.secret_key, algorithms=['HS256'])
     
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


def guardar_token(U_id, token, fecha_creacion, fecha_expiracion):
 
 with pyodbc.connect(connection_string2) as connection:
  cursor = connection.cursor()
  # Consulta para guardar el token
  sql = """
   INSERT INTO tokens (usuario_id, token, fecha_creacion, fecha_expiracion)
   VALUES (?, ?, ?, ?)
  """
  cursor.execute(sql, [U_id, token, fecha_creacion, fecha_expiracion])
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







