import csv, bcrypt, secrets, random
from faker import Faker
from tqdm import tqdm
from datetime import datetime, timedelta

CANT = 70_000
SALT_ROUNDS = 12          # bcrypt rounds (mismo que Flask-Bcrypt por defecto)
faker  = Faker()
Faker.seed(0)             # reproducible

def fake_date():
    # fecha entre hoy y 2 años atrás
    return faker.date_time_between(start_date='-2y', end_date='now')

def fake_active():
    return random.choice([True, True, False])   # 66 % activos

def hash_pwd(pwd: str) -> str:
    # devuelve hash bcrypt con prefijo $2b$
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt(rounds=SALT_ROUNDS)).decode()

with open('users_70k.csv', 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f, delimiter='|')
    writer.writerow(['id','username','email','password_hash','is_active','created_at','updated_at'])

    for i in tqdm(range(1, CANT+1), desc='Generando'):
        username = faker.user_name() + str(random.randint(10, 9999))   # evitar duplicados
        email    = faker.email()
        pwd_hash = hash_pwd('Pass123!')   # misma contraseña para todos (prueba)
        active   = fake_active()
        created  = fake_date()
        updated  = created + timedelta(seconds=random.randint(0, 86400*30))

        writer.writerow([i, username, email, pwd_hash, active,
                         created.isoformat(sep=' ', timespec='seconds'),
                         updated.isoformat(sep=' ', timespec='seconds')])
print('Archivo users_70k.csv listo ✅')
