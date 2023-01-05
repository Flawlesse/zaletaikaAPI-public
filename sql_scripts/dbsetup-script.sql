-- Don't forget to CREATE EXTENSION postgis;

-- USER AUTHENTICATION
CREATE TABLE IF NOT EXISTS AppUser(
    id bigint GENERATED ALWAYS AS IDENTITY,
    username varchar(200) UNIQUE NOT NULL,
    email varchar(256) UNIQUE NOT NULL,
    password varchar(256) NOT NULL,
    birthDate date NOT NULL,
    avatar varchar(30) NOT NULL 
        CHECK (avatar IN 
            ('BROWN_HAIR', 'BLOND_HAIR', 
            'DARK_SKIN', 'RED_HAIR', 'HIJAB')
        ) DEFAULT 'HIJAB',
    firstName varchar(100) NOT NULL,
    lastName varchar(100) NOT NULL,

    PRIMARY KEY(id)
);
CREATE TABLE IF NOT EXISTS AuthToken(
    id bigint GENERATED ALWAYS AS IDENTITY,
    userId bigint,
    token varchar(100) NOT NULL,

    PRIMARY KEY(id),
    CONSTRAINT authtoken_fk_user 
        FOREIGN KEY(userId)
        REFERENCES AppUser(id)
        ON DELETE CASCADE
);

-- USER GROUPS
CREATE TABLE IF NOT EXISTS AdminGroup(
    id bigint GENERATED ALWAYS AS IDENTITY,
    userId bigint UNIQUE NOT NULL,

    PRIMARY KEY(id),
    CONSTRAINT admingroup_fk_user 
        FOREIGN KEY(userId)
        REFERENCES AppUser(id)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS DoctorGroup(
    id bigint GENERATED ALWAYS AS IDENTITY,
    userId bigint UNIQUE NOT NULL,
    occupation varchar(200) NOT NULL,
    isVerified boolean NOT NULL DEFAULT false,

    PRIMARY KEY(id),
    CONSTRAINT doctorgroup_fk_user 
        FOREIGN KEY(userId)
        REFERENCES AppUser(id)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS PatientGroup(
    id bigint GENERATED ALWAYS AS IDENTITY,
    userId bigint UNIQUE NOT NULL,
    doctorGID bigint DEFAULT NULL, -- doctor could be unassigned for some time
    dateOfPregnancy date NOT NULL,

    PRIMARY KEY(id),
    CONSTRAINT patientgroup_fk_user 
        FOREIGN KEY(userId)
        REFERENCES AppUser(id)
        ON DELETE CASCADE,
    CONSTRAINT patientgroup_fk_doctorgroup
        FOREIGN KEY(doctorGID)
        REFERENCES DoctorGroup(id)
        ON DELETE SET NULL
);

-- PATIENT-DOCTOR CHAT
CREATE TABLE IF NOT EXISTS Conversation(
    id bigint GENERATED ALWAYS AS IDENTITY,
    patientGID bigint UNIQUE NOT NULL,

    PRIMARY KEY(id),
    CONSTRAINT conversation_fk_patientgroup
        FOREIGN KEY(patientGID)
        REFERENCES PatientGroup(id)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS Message(
    id bigint GENERATED ALWAYS AS IDENTITY,
    conversationId bigint NOT NULL,
    content text NOT NULL,
    timePosted timestamp with time zone NOT NULL DEFAULT current_timestamp,
    readTime timestamp with time zone,
    isFromPatient boolean NOT NULL,

    PRIMARY KEY(id),
    CONSTRAINT message_fk_conversation
        FOREIGN KEY(conversationId)
        REFERENCES Conversation(id)
        ON DELETE CASCADE
);

-- VIDEO MEETINGS & TIMESLOTS
CREATE TABLE IF NOT EXISTS TimeSlot(
    id bigint GENERATED ALWAYS AS IDENTITY,
    bookingTime timestamp with time zone NOT NULL, 
    additionalDescription text NOT NULL DEFAULT '',
    doctorGID bigint NOT NULL,
    bookedByPatientGID bigint NOT NULL,

    PRIMARY KEY (id),
    CONSTRAINT timeslot_fk_doctorgroup
        FOREIGN KEY(doctorGID)
        REFERENCES DoctorGroup(id)
        ON DELETE CASCADE,
    CONSTRAINT timeslot_fk_patientgroup
        FOREIGN KEY(bookedByPatientGID)
        REFERENCES PatientGroup(id)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS VideoMeeting(
    id bigint GENERATED ALWAYS AS IDENTITY,
    roomName varchar(200) UNIQUE NOT NULL,
    timeslotId bigint UNIQUE NOT NULL,

    PRIMARY KEY (id),
    CONSTRAINT videomeeting_fk_timeslot
        FOREIGN KEY(timeslotId)
        REFERENCES TimeSlot(id)
        ON DELETE CASCADE
);

-- SOSREQUESTS & LOGS
CREATE TABLE IF NOT EXISTS SOSRequest(
    id bigint GENERATED ALWAYS AS IDENTITY,
    geopos geometry(Point, 4326) NOT NULL,
    patientGID bigint NOT NULL,
    timeHappened timestamp with time zone NOT NULL DEFAULT current_timestamp,
    isResolved boolean NOT NULL DEFAULT false,

    PRIMARY KEY (id),
    CONSTRAINT sosrequest_fk_patientgroup
        FOREIGN KEY(patientGID)
        REFERENCES PatientGroup(id)
        ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS Logs(
    id bigint GENERATED ALWAYS AS IDENTITY,
    type varchar(30) NOT NULL
        CHECK (type in (
            'INFO', 'WARN', 
            'ERR', 'FATAL')
        ),
    message text NOT NULL DEFAULT '',
    stackTrace text,
    timeHappened timestamp with time zone NOT NULL DEFAULT current_timestamp,

    PRIMARY KEY (id)
);

-- ARTICLE, MENU, EXERCISE
CREATE TABLE IF NOT EXISTS Article(
    id bigint GENERATED ALWAYS AS IDENTITY,
    title varchar(100) NOT NULL,
    content text NOT NULL,
    publicationDate date NOT NULL DEFAULT current_date,
    image varchar(1000),
    category varchar(100),

    PRIMARY KEY (id)
);
CREATE TABLE IF NOT EXISTS Menu(
    id bigint GENERATED ALWAYS AS IDENTITY,
    title varchar(100) NOT NULL,
    content text NOT NULL,
    publicationDate date NOT NULL DEFAULT current_date,
    image varchar(1000),
    category varchar(100),

    PRIMARY KEY (id)
);
CREATE TABLE IF NOT EXISTS Exercise(
    id bigint GENERATED ALWAYS AS IDENTITY,
    title varchar(100) NOT NULL,
    content text NOT NULL,
    video varchar(1000),
    publicationDate date NOT NULL DEFAULT current_date,
    image varchar(1000),
    category varchar(100),

    PRIMARY KEY (id)
);

-- WORKOUT
CREATE TABLE IF NOT EXISTS Workout(
    id bigint GENERATED ALWAYS AS IDENTITY,
    createdDate date NOT NULL DEFAULT current_date,
    daysPerWeek int NOT NULL
        CHECK (daysPerWeek > 0 AND daysPerWeek < 8),
    description text NOT NULL,
    image varchar(1000),
    title varchar(100) NOT NULL,
    category varchar(20) NOT NULL 
        CHECK (category IN ('REHAB', 'PHYSICAL')),
    patientGID bigint NOT NULL,

    PRIMARY KEY (id),
    CONSTRAINT workout_fk_patientgroup
        FOREIGN KEY (patientGID)
        REFERENCES PatientGroup(id)
        ON DELETE CASCADE
);

-- EXERCISE-M2M-WORKOUT
CREATE TABLE IF NOT EXISTS ExerciseInWorkout(
    id bigint GENERATED ALWAYS AS IDENTITY,
    exerciseId bigint NOT NULL,
    workoutId bigint NOT NULL,
    position int NOT NULL 
        CHECK (position >= 0),

    PRIMARY KEY (id),
    CONSTRAINT exerciseinworkout_fk_exercise
        FOREIGN KEY (exerciseId)
        REFERENCES Exercise(id)
        ON DELETE CASCADE,
    CONSTRAINT exerciseinworkout_fk_workout
        FOREIGN KEY (workoutId)
        REFERENCES Workout(id)
        ON DELETE CASCADE
);


-- VIEWS SECTION


CREATE OR REPLACE VIEW appuser_with_GIDs AS
    SELECT AppUser.id as myid, AdminGroup.id as admin_gid, 
        DoctorGroup.id as doctor_gid, PatientGroup.id as patient_gid
    FROM AppUser
    LEFT JOIN AdminGroup ON AppUser.id = AdminGroup.userId
    LEFT JOIN DoctorGroup ON AppUser.id = DoctorGroup.userId
    LEFT JOIN PatientGroup ON AppUser.id = PatientGroup.userId;

CREATE OR REPLACE VIEW conversation_message_view AS
    SELECT Conversation.id as conversation_id, 
        Conversation.patientGID as conversation_patient_gid,
        Message.id as message_id, Message.content as message_content,
        Message.timePosted as message_time_posted,
        Message.readTime IS NOT NULL as message_is_read, 
        Message.readTime as message_read_time, 
        Message.isFromPatient as message_is_from_patient
    FROM Message
    JOIN Conversation ON Conversation.id = Message.conversationId;

CREATE OR REPLACE VIEW videomeeting_info_view AS
    SELECT TimeSlot.id as timeslot_id, VideoMeeting.id as videomeeting_id,
        TimeSlot.bookingTime as booking_time, 
        TimeSlot.additionalDescription as additional_description,
        TimeSlot.doctorGID as doctor_gid,
        TimeSlot.bookedByPatientGID as patient_gid,
        VideoMeeting.roomName as room_name
    FROM TimeSlot
    JOIN VideoMeeting ON TimeSlot.id = VideoMeeting.timeslotId;


-- FUNCTIONS SECTION


CREATE OR REPLACE FUNCTION get_appuser_group(appuserId bigint)
RETURNS varchar AS $$
DECLARE
    r record;
    group_name varchar;
BEGIN
    group_name := 'NONE';
    r := row(NULL);
    SELECT myid, admin_gid, doctor_gid, patient_gid
    INTO r FROM appuser_with_GIDs
    WHERE myid = appuserId;
    
    IF r IS NULL THEN
        RAISE EXCEPTION 'No user with id=% found!', appuserId;
    END IF;
    IF r.admin_gid IS NOT NULL THEN
        group_name := 'ADMIN';
    ELSIF r.doctor_gid IS NOT NULL THEN
        group_name := 'DOCTOR';
    ELSIF r.patient_gid IS NOT NULL THEN
        group_name := 'PATIENT';
    ELSE
        RAISE EXCEPTION 'User id=% is corrupted!', appuserId;
    END IF;
    RETURN group_name;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_userid_by_token(passedToken varchar)
RETURNS bigint AS $$
DECLARE
    resultId bigint;
BEGIN
    resultId := NULL;
    SELECT userId 
    INTO resultId FROM AuthToken
    WHERE token = passedToken;
    IF resultId IS NULL THEN
        RAISE EXCEPTION 'Token does not exist.';
    END IF;
    RETURN resultId;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_appuser_gid_role(appuserId bigint, OUT appuserGID bigint, OUT appuserRole varchar)
AS $$
BEGIN
    SELECT get_appuser_group(appuserId) INTO appuserRole;
    SELECT COALESCE(admin_gid, doctor_gid, patient_gid) 
    INTO appuserGID FROM appuser_with_GIDs
    WHERE myid = appuserId;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION update_appuser_email(passedToken varchar, newEmail varchar)
RETURNS VOID AS $$
BEGIN
    UPDATE AppUser SET email = newEmail WHERE id = get_userid_by_token(passedToken);
END;
$$ LANGUAGE plpgsql;






CREATE OR REPLACE FUNCTION is_doctor_verified(doctorGID bigint)
RETURNS BOOLEAN AS $$
DECLARE
    result boolean;
BEGIN
    SELECT isVerified INTO result FROM DoctorGroup
    WHERE id = doctorGID;
    IF result IS NULL THEN
        RAISE EXCEPTION 'Doctor with GID=% not found!', doctorGID;
    END IF;
    RETURN result;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION is_patient_allowed_to_login(patientGID bigint)
RETURNS BOOLEAN AS $$
DECLARE
    result boolean;
BEGIN
    SELECT doctorGID IS NOT NULL INTO result FROM PatientGroup
    WHERE id = patientGID;
    IF result IS NULL THEN
        RAISE EXCEPTION 'Patient with GID=% not found!', patientGID;
    END IF;
    RETURN result;
END;
$$ LANGUAGE plpgsql;






CREATE OR REPLACE FUNCTION get_conversation_id(_patientGID bigint)
RETURNS bigint AS $$
DECLARE
    result bigint;
BEGIN
    SELECT id INTO result FROM Conversation WHERE patientGID = _patientGID;
    IF result IS NULL THEN
        RAISE EXCEPTION 'Patient with GID=% has no conversation assigned. Corrupted user!', _patientGID;
    END IF;
    RETURN result; 
END;
$$ LANGUAGE plpgsql;


CREATE OR REPLACE FUNCTION get_message_info(message_id bigint)
RETURNS TABLE (
    id bigint, content text, from_name varchar, 
    is_from_patient boolean, read_time timestamp with time zone, 
    time_posted timestamp with time zone
) AS $$
DECLARE
    _conversationId bigint;
    _content text;
    _timePosted timestamp with time zone;
    _readTime timestamp with time zone;
    _isFromPatient boolean;
    from_name varchar;

    related_doctor_GID bigint;
BEGIN
    SELECT Message.conversationId, Message.content, Message.timePosted, 
        Message.readTime, Message.isFromPatient  
    INTO _conversationId, _content, _timePosted, _readTime, _isFromPatient FROM Message 
    WHERE Message.id = message_id;
    
    IF _isFromPatient THEN 
        SELECT AppUser.firstName || ' ' || AppUser.lastName INTO from_name
        FROM AppUser
        JOIN PatientGroup ON AppUser.id = PatientGroup.userId
        JOIN Conversation ON PatientGroup.id = Conversation.patientGID
        WHERE Conversation.id = _conversationId;
    ELSE
        -- Find the doctor related to this conversation
        SELECT PatientGroup.doctorGID INTO related_doctor_GID
        FROM Conversation
        JOIN PatientGroup ON Conversation.patientGID = PatientGroup.id
        WHERE Conversation.id = _conversationId;
        -- Use his GID to find his full name
        SELECT AppUser.firstName || ' ' || AppUser.lastName INTO from_name
        FROM AppUser
        JOIN DoctorGroup ON AppUser.id = DoctorGroup.userId
        WHERE DoctorGroup.id = related_doctor_GID;
    END IF;
    RETURN QUERY
    SELECT message_id, _content, from_name, _isFromPatient, _readTime, _timePosted;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION patient_get_conversation_info(patient_gid bigint)
RETURNS TABLE (
    employee_name varchar, employee_occupation varchar, 
    employee_profile_picture varchar, unread_messages_count int
) AS $$
DECLARE
    employee_name varchar;
    employee_occupation varchar;
    employee_profile_picture varchar;
    unread_messages_count int;

    conversation_id bigint;
    related_doctor_GID bigint;
BEGIN
    -- Get doctor gid
    SELECT doctorGID INTO related_doctor_GID
    FROM PatientGroup 
    WHERE id = patient_gid;
    -- Get info about him
    SELECT AppUser.firstName || ' ' || AppUser.lastName, 
        DoctorGroup.occupation, AppUser.avatar
    INTO employee_name, employee_occupation, employee_profile_picture
    FROM AppUser
    JOIN DoctorGroup ON DoctorGroup.userId = AppUser.id
    WHERE DoctorGroup.id = related_doctor_GID;
    -- Get count of unread messages
    SELECT COUNT(*) INTO unread_messages_count
    FROM conversation_message_view
    WHERE conversation_patient_gid = patient_gid
        AND NOT message_is_from_patient
        AND NOT message_is_read;
    -- Store results and return
    RETURN QUERY
    SELECT employee_name, employee_occupation,
        employee_profile_picture, unread_messages_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION doctor_get_conversation_info(conversation_id bigint)
RETURNS TABLE (
    patient_name varchar, patient_date_of_pregnancy date,
    patient_profile_picture varchar, unread_messages_count int
) AS $$
DECLARE
    patient_name varchar;
    patient_date_of_pregnancy date;
    patient_profile_picture varchar;
    unread_messages_count int;

    related_patient_GID bigint;
BEGIN
    -- Get patient gid
    SELECT patientGID INTO related_patient_GID
    FROM Conversation
    WHERE id = conversation_id;
    -- Get info about her
    SELECT AppUser.firstName || ' ' || AppUser.lastName, 
        PatientGroup.dateOfPregnancy, AppUser.avatar
    INTO patient_name, patient_date_of_pregnancy, patient_profile_picture
    FROM AppUser
    JOIN PatientGroup ON PatientGroup.userId = AppUser.id
    WHERE PatientGroup.id = related_patient_GID;
    -- Get count of unread messages
    SELECT COUNT(*) INTO unread_messages_count
    FROM conversation_message_view
    WHERE conversation_patient_gid = related_patient_GID
        AND message_is_from_patient
        AND NOT message_is_read;
    -- Store results and return
    RETURN QUERY
    SELECT patient_name, patient_date_of_pregnancy,
        patient_profile_picture, unread_messages_count;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION get_doctor_related_conversation_ids(doctor_gid bigint)
RETURNS TABLE (conversation_id bigint) AS $$
BEGIN
    RETURN QUERY
    SELECT Conversation.id 
    FROM PatientGroup
    JOIN Conversation ON PatientGroup.id = Conversation.patientGID 
    WHERE PatientGroup.doctorGID = doctor_gid;
END;
$$ LANGUAGE plpgsql;




-- Seems to be working fine
CREATE OR REPLACE FUNCTION get_booked_meetings(
    is_patient_request boolean, gid bigint, for_today boolean
) RETURNS TABLE (
    id bigint, timeslot_id bigint, 
    booking_time timestamp with time zone, 
    _enabled boolean, title text
) AS $$
BEGIN
    -- REMEMBER THAT EVERY TIME THE PATIENT CHANGES THE DOCTOR
    -- ALL THE RELATED TIMESLOTS ARE ERASED THROUGH OUR BACKEND!!!

    -- if not for_today then observable interval is 2 weeks
    -- else, only current hour - end of work day
    IF is_patient_request THEN
        -- if it is a patient's request, get all of her booked meetings
        -- and extract her doctor's full name as title
        IF for_today THEN
            RETURN QUERY
            SELECT videomeeting_info_view.videomeeting_id as id, 
                videomeeting_info_view.timeslot_id as timeslot_id,
                videomeeting_info_view.booking_time as booking_time,
                current_timestamp >= videomeeting_info_view.booking_time 
                    AND current_timestamp <= videomeeting_info_view.booking_time + interval '1 hour' 
                    as _enabled,
                AppUser.firstName || ' ' || AppUser.lastName  as title
            FROM videomeeting_info_view
            JOIN DoctorGroup ON videomeeting_info_view.doctor_gid = DoctorGroup.id
            JOIN AppUser ON DoctorGroup.userId = AppUser.id
            WHERE videomeeting_info_view.patient_gid = gid
                AND videomeeting_info_view.booking_time >= date_trunc('hour', current_timestamp)
                AND videomeeting_info_view.booking_time <= (current_timestamp::date + interval '1 day')::timestamptz;
        ELSE
            RETURN QUERY
            SELECT videomeeting_info_view.videomeeting_id as id, 
                videomeeting_info_view.timeslot_id as timeslot_id,
                videomeeting_info_view.booking_time as booking_time,
                current_timestamp >= videomeeting_info_view.booking_time 
                    AND current_timestamp <= videomeeting_info_view.booking_time + interval '1 hour' 
                    as _enabled,
                AppUser.firstName || ' ' || AppUser.lastName  as title
            FROM videomeeting_info_view
            JOIN DoctorGroup ON videomeeting_info_view.doctor_gid = DoctorGroup.id
            JOIN AppUser ON DoctorGroup.userId = AppUser.id
            WHERE videomeeting_info_view.patient_gid = gid
                AND videomeeting_info_view.booking_time >= date_trunc('hour', current_timestamp)
                AND videomeeting_info_view.booking_time <= (current_timestamp::date + interval '2 weeks')::timestamptz;
        END IF;
    ELSE
        -- if it is a doctor's request, get all of his booked meetings
        -- and extract the respectful patient's full name as title
        IF for_today THEN
            RETURN QUERY
            SELECT videomeeting_info_view.videomeeting_id as id, 
                videomeeting_info_view.timeslot_id as timeslot_id,
                videomeeting_info_view.booking_time as booking_time,
                current_timestamp >= videomeeting_info_view.booking_time 
                    AND current_timestamp <= videomeeting_info_view.booking_time + interval '1 hour' 
                    as _enabled,
                AppUser.firstName || ' ' || AppUser.lastName  as title
            FROM videomeeting_info_view
            JOIN PatientGroup ON videomeeting_info_view.patient_gid = PatientGroup.id
            JOIN AppUser ON PatientGroup.userId = AppUser.id
            WHERE videomeeting_info_view.doctor_gid = gid
                AND videomeeting_info_view.booking_time >= date_trunc('hour', current_timestamp)
                AND videomeeting_info_view.booking_time <= (current_timestamp::date + interval '1 day')::timestamptz;
        ELSE
            RETURN QUERY
            SELECT videomeeting_info_view.videomeeting_id as id, 
                videomeeting_info_view.timeslot_id as timeslot_id,
                videomeeting_info_view.booking_time as booking_time,
                current_timestamp >= videomeeting_info_view.booking_time 
                    AND current_timestamp <= videomeeting_info_view.booking_time + interval '1 hour' 
                    as _enabled,
                AppUser.firstName || ' ' || AppUser.lastName  as title
            FROM videomeeting_info_view
            JOIN PatientGroup ON videomeeting_info_view.patient_gid = PatientGroup.id
            JOIN AppUser ON PatientGroup.userId = AppUser.id
            WHERE videomeeting_info_view.doctor_gid = gid
                AND videomeeting_info_view.booking_time >= date_trunc('hour', current_timestamp)
                AND videomeeting_info_view.booking_time <= (current_timestamp::date + interval '2 weeks')::timestamptz;
        END IF;
    END IF;
END;
$$ LANGUAGE plpgsql;


-- Seems to be working fine, but not in python
CREATE OR REPLACE FUNCTION can_patient_book_meeting(
    patient_gid bigint, booking_time_passed timestamp with time zone,
    _context varchar
) RETURNS boolean AS $$
DECLARE
    result record;
    doctor_gid bigint;
BEGIN
    -- Get doctor meetings and look for one that matches exact time
    IF booking_time_passed < current_timestamp 
    OR booking_time_passed > (current_timestamp::date + interval '2 weeks')::timestamptz 
    THEN
        RETURN false;
    END IF;
    SELECT doctorGID INTO doctor_gid 
    FROM PatientGroup WHERE id = patient_gid;
    IF doctor_gid IS NULL THEN
        RAISE EXCEPTION 'Patient has no doctor assigned to her yet.';
    END IF;
    -- So if we don't find the booked meeting for this time
    -- then patient can indeed book a meeting for herself
    SELECT * INTO result 
    FROM get_booked_meetings(false, doctor_gid, false)
    WHERE booking_time = booking_time_passed;
    RETURN result IS NULL;
END;
$$ LANGUAGE plpgsql;


-- select * from can_patient_book_meeting(1, to_timestamp('2022-12-19 10:00:00', 'YYYY-MM-DD HH24:MI:SS')::timestamptz, 'SQL');
-- select * from can_patient_book_meeting(1, (to_timestamp('2022-12-19 10:00:00', 'YYYY-MM-DD HH24:MI:SS') at time zone interval '+0')::timestamptz, 'SQL');
-- select * from can_patient_book_meeting(1, to_timestamp('2022-12-19 10:00:00', 'YYYY-MM-DD HH24:MI:SS') at time zone interval '+0' at time zone interval '+3.00' + interval '3 seconds' , 'SQL');
-- select (to_timestamp('2022-12-19 10:00:00', 'YYYY-MM-DD HH24:MI:SS')::timestamp at time zone interval '+0' at time zone interval '+3.00' - interval '3 seconds')::timestamptz;
-- select * from can_patient_book_meeting(1, timestamptz '2022-12-19 10:00:00 +3', 'SQL');


-- select * from logs order by id desc limit 1;
-- select (timestamptz '2022-12-19 07:00:00 +0' at time zone 'Europe/Minsk')::timestamptz;