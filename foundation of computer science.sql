mysql> CREATE TABLE Student (
    ->     StudentID   INT PRIMARY KEY,
    ->     StudentName VARCHAR(100) NOT NULL,
    ->     Email       VARCHAR(150) NOT NULL
    -> );

mysql> CREATE TABLE Club (
    ->     ClubID      VARCHAR(10) PRIMARY KEY,
    ->     ClubName    VARCHAR(100) NOT NULL,
    ->     ClubRoom    VARCHAR(20),
    ->     ClubMentor  VARCHAR(100)
    -> );

mysql> CREATE TABLE Membership (
    ->     MembershipID INT PRIMARY KEY,
    ->     StudentID    INT NOT NULL,
    ->     ClubID       VARCHAR(10) NOT NULL,
    ->     JoinDate     DATE NOT NULL,
    ->     FOREIGN KEY (StudentID) REFERENCES Student(StudentID),
    ->     FOREIGN KEY (ClubID)    REFERENCES Club(ClubID)
    -> );

 mysql> INSERT INTO Student (StudentID, StudentName, Email)
    -> VALUES (8, 'Priya', 'priya@email.com');
mysql> INSERT INTO Club (ClubID, ClubName, ClubRoom, ClubMentor)
    -> VALUES ('C5', 'Photography Club', 'R404', 'Ms. Lata');
mysql> SELECT * FROM Student;
mysql> SELECT * FROM Club;

