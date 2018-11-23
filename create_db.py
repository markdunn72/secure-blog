import datetime
import os
import sqlite3
import string
import random
import lipsum
import re

DATABASE = 'blogsite.sqlite'

# From http://listofrandomnames.com/index.cfm?textarea
USERS=map(lambda x:x.strip(), re.split('[\r\n]+','''Aleida King  
Billye Quayle  
Mildred Beaty  
Adeline Beyers  
Tricia Wendel  
Kizzy Bedoya  
Marx Warn  
Hulda Culberson  
Devona Morvant  
Winston Tomasello  
Dede Frame  
Lissa Follansbee  
Timmy Dapolito  
Gracie Lonon  
Nana Officer  
Yuri Kruchten  
Chante Brasch  
Edmond Toombs  
Scott Schwan  
Lean Beauregard  
Norberto Petersen  
Carole Costigan  
Chantel Drumheller  
Riva Redfield  
Jennie Sandifer  
Vivian Cimini  
Goldie Hayworth  
Tomeka Kimler  
Micaela Juan  
Jerrold Tjaden  
Collene Olson  
Edna Serna  
Cleveland Miley  
Ena Haecker  
Huey Voelker  
Annamae Basco  
Florentina Quinlan  
Eryn Chae  
Mozella Mcknight  
Ruby Cobble  
Jeannine Simerly  
Colby Tabares  
Jason Castorena  
Asia Mosteller  
Betsy Mendelsohn  
Nicolle Leverette  
Bobette Tuel  
Lizabeth Borchert  
Danica Halverson  
Consuelo Crown'''))

def create():
    db = sqlite3.connect(DATABASE)

    c = db.cursor()

    c.execute(
        'CREATE TABLE USERS'
        '(USERID INTEGER PRIMARY KEY, USERNAME TEXT NOT NULL UNIQUE, '
        'PASSWORD TEXT NOT NULL, EMAIL TEXT NOT NULL UNIQUE, CONFIRMED INTEGER NOT NULL);')
    c.execute(
        'CREATE TABLE POSTS'
        '(POSTID INTEGER PRIMARY KEY, CREATOR INTEGER NOT NULL REFERENCES USERS(USERID), '
        'DATE INTEGER, TITLE TEXT NOT NULL, CONTENT TEXT NOT NULL)')
    c.execute('''CREATE INDEX USER_USERNAME on USERS (USERNAME)''')
    c.execute('''CREATE INDEX USER_POSTS on POSTS (CREATOR,DATE)''')
    db.commit()

    id = 0
    for user in USERS:
        create_content(db, id, user)
        id += 1
    db.commit()


def create_content(db, id, name):
    password = 'password'
    c = db.cursor()
    username = '%s%s' % (name.lower()[0], name.lower()[name.index(' ') + 1:])
    email = '%s.%s@email.com' % ((name.lower()[0], name.lower()[name.index(' ') + 1:]))
    c.execute('INSERT INTO USERS (userid, username, password, email, confirmed) VALUES (?,?,?,?, ?)',
              (id, username, password, email, 1))
    date = datetime.datetime.now() - datetime.timedelta(28)

    for i in range(random.randrange(4, 8)):
        content = lipsum.generate_paragraphs(random.randrange(2, 6))
        title = lipsum.generate_words(8)
        date = date + datetime.timedelta(random.randrange(1, 3), minutes=random.randrange(1, 120),
                                         hours=random.randrange(0, 6))

        c.execute('INSERT INTO posts (creator,date,title,content) VALUES (?,?,?,?)',
                  (id, date.timestamp(), title, content))

def delete_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)


if __name__ == '__main__':
    delete_db()
    create()