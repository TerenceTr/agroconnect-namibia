-- ==================================================================
--  AGROCONNECT NAMIBIA – USERS TABLE
--  PostgreSQL Schema + Clean Insert Data
--  Date Range: 01 Aug 2025 → 10 Oct 2025
-- ==================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS users CASCADE;

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    full_name VARCHAR(200) NOT NULL,
    phone VARCHAR(20) NOT NULL UNIQUE,
    email VARCHAR(200) NOT NULL UNIQUE,
    location VARCHAR(150),
    password_hash VARCHAR(255) NOT NULL,
    role INTEGER NOT NULL,                  -- 1=Farmer, 2=Customer, 3=Trader/Buyer
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    deleted_at TIMESTAMP NULL
);

-- =====================================================================
-- INSERT USER DATA (with fresh realistic timestamps)
-- =====================================================================

INSERT INTO users (id, full_name, phone, email, location, password_hash, role, created_at, updated_at, is_active, deleted_at)
VALUES
('8c325faa-e2f1-4c92-b48b-720f7199d8bb','Mekondjo Nuuyoma','0810123456','mekondjo.nuuyoma@gmail.com','Etunda',
 '$2b$12$mLbnLJCRjWMQgAP5Eo22Q.uJ2o/PUMjYWzTcGGYZ6VhN0Nm4KKAwK',2,
 '2025-08-05 10:22:11','2025-09-28 14:44:01',TRUE,NULL),

('05fa5925-c325-4e88-9143-5d522a9ccee6','Maria Mungeli','0816543210','maria.mungeli@gmail.com','Rundu',
 '$2b$12$do/GrWtqvLpDxxbs8mj1X.dmsSnQBDQusvb7o6YQG27A1DSTRnNlG',2,
 '2025-08-12 09:15:43','2025-10-02 17:51:20',TRUE,NULL),

('33ddf062-6e25-4d39-9582-d23c6de9f19b','Mushaukwa Ntelamo','0814006000','conardntelamo11@gmail.com','Katima Mulilo',
 '$2b$12$kHAr5uPh.MFIjNXNYTuYQ.eK0kyWVE1z/dMlvpTF384ESZ5t1v3by',2,
 '2025-09-03 08:41:52','2025-10-05 15:33:19',TRUE,NULL),

('04e49484-c554-491e-8b5c-9e2633af694a','Anton Van Wyk','0812233455','anton.vanwyk@gmail.com','Rehoboth',
 '$2b$12$D9f1P.Y4KRoKrV8yQDTfyOqq9.9sl2kixZ8iCHHi5Tpyv5ESTFBoe',2,
 '2025-08-29 13:22:09','2025-09-30 16:27:44',TRUE,NULL),

('8089381d-495b-4202-a82a-1d2ca54a9185','Nzwana Situmbeko','0812000345','nzwana.situmbeko@gmail.com','Windhoek',
 '$2b$12$KXepCTwhfE6RhS7qYx1v.ewJGNQhBBJBiy0jtTesX6JItiDkFG62m',3,
 '2025-09-11 11:12:55','2025-10-06 18:22:51',TRUE,NULL),

('e03a47ff-c0ee-4ade-8078-7dbf0d2eac50','Mushabati Ntelamo','0815566789','mushabati.ntelamo@gmail.com','Ongwediva',
 '$2b$12$0KZQN8B2syN/AI0MiaDoteGE5Jr6VYq8v/5MvKCfQV407qc9D8P9K',3,
 '2025-08-07 07:19:08','2025-09-29 19:45:02',TRUE,NULL),

('3ff20f76-d9e8-42c6-817e-5d3e13c0048d','Catherine Situmbeko','0815566778','catherine.situmbeko@gmail.com','Windhoek',
 '$2b$12$Oy/CMN1OKjIDV3mwRTM8UO4vP1ik4weupfjHJVImWPonAbcii/kuC',3,
 '2025-09-15 10:55:49','2025-10-08 13:19:33',TRUE,NULL),

('f673233a-b98f-4b49-8ce6-fcc818d4412a','Conard Ntelamo','0814006117','tcntelamo@gmail.com','Ongwediva',
 '$2b$12$3XBmJiUlYNLTU4byZBrQW.pQzSajOiardMfyIvptACQN8JqstjIuy',1,
 '2025-08-25 09:03:22','2025-10-03 11:45:18',TRUE,NULL),

('429c92d1-c420-4658-88b1-4fd825d79128','Admin','0814006100','admin@agroconnect.com','Head Office',
 '$2b$12$01LuP5vCHog0nhNG8Z1bUevPoz3eBhlnmNdkdUmZmBG3ruyPkQMgG',1,
 '2025-08-01 08:00:00','2025-09-20 09:33:42',TRUE,NULL),

('b9195d1e-d31e-4651-ba72-ae7ac86dee69','Martha Armas','0812345678','marthaarmas@gmail.com','Oshakati',
 '$2b$12$ycUyqGQht5ojkkyPICiYzuRZXduVVHeNR//1V26hTfWx1GShMW4yO',3,
 '2025-09-07 14:19:31','2025-10-09 16:10:27',TRUE,NULL);
 
DROP TABLE IF EXISTS products CASCADE;

CREATE TABLE products (
    product_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_name VARCHAR(200) NOT NULL,
    description TEXT,
    price NUMERIC(10,2) NOT NULL,
    quantity INTEGER NOT NULL,
    image_url TEXT,
    category VARCHAR(100),
    status VARCHAR(50) DEFAULT 'available',
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
); 
INSERT INTO products (product_id, user_id, product_name, description, price, quantity, image_url, category, status, created_at)
VALUES
('099d03d8-79c1-4426-8052-0e65e9a70521','8c325faa-e2f1-4c92-b48b-720f7199d8bb','Mahangu (Pearl Millet)','Drought-resistant staple grain, harvested fresh from Etunda fields.',120.00,80,'default/millet.jpg','grain','available','2025-11-12 14:37:27'),
('0ffd7ac8-0ccc-41d0-ae17-147c21e4cd99','8c325faa-e2f1-4c92-b48b-720f7199d8bb','Maize','Yellow maize cobs, ideal for porridge or mealie meal.',180.00,50,'default/maize.jpg','grain','available','2025-11-12 14:37:27'),
('15b5c76f-4536-401f-b059-12b1752118f3','8c325faa-e2f1-4c92-b48b-720f7199d8bb','Carrots','Fresh orange root carrots, grown with groundwater irrigation.',15.00,40,'default/carrot.jpg','root','available','2025-11-12 14:37:27'),
('9e741ad5-3f6c-4fbd-962b-43404a325a74','8c325faa-e2f1-4c92-b48b-720f7199d8bb','Potatoes','Red-skinned potatoes, suitable for boiling or chips.',25.00,30,'default/potato.jpg','root','available','2025-11-12 14:37:27'),
('22b1384e-41f8-4be6-b9b1-257d7327499b','05fa5925-c325-4e88-9143-5d522a9ccee6','Cowpeas (Beans)','Protein-rich black-eyed beans, traditional Rundu variety.',100.00,60,'default/beans.jpg','legume','available','2025-11-12 14:37:27'),
('f7118be9-de5e-483e-953f-68310f1b9879','05fa5925-c325-4e88-9143-5d522a9ccee6','Sorghum','White sorghum grain for baking or brewing.',140.00,70,'default/sorghum.jpg','grain','available','2025-11-12 14:37:27'),
('6f5f1988-6f9d-4d7a-a271-5a9b83cded9c','05fa5925-c325-4e88-9143-5d522a9ccee6','Onions','Red onions, Namibia''s top vegetable crop – crisp and storage-friendly.',10.00,120,'default/onion.jpg','vegetable','available','2025-11-12 14:37:27'),
('fb816ea6-30fc-415a-9d03-eab94ada9f9f','33ddf062-6e25-4d39-9582-d23c6de9f19b','Tomatoes','Ripe red tomatoes from Caprivi floodplains.',15.00,100,'default/tomato.jpg','vegetable','available','2025-11-12 14:37:27'),
('3df3eb15-4231-430e-98f3-fb06176f19ab','33ddf062-6e25-4d39-9582-d23c6de9f19b','Cabbage','Green cabbages, perfect for salads or stews.',20.00,50,'default/cabbage.jpg','vegetable','available','2025-11-12 14:37:27'),
('ac16c6ca-4da1-41b8-a761-4439959b73c3','33ddf062-6e25-4d39-9582-d23c6de9f19b','Peas','Green peas in pods, fresh-picked for market.',18.00,25,'default/peas.jpg','legume','available','2025-11-12 14:37:27'),
('508ef5c4-8327-419d-b997-e271cbe1b807','04e49484-c554-491e-8b5c-9e2633af694a','Onions','White onions from Rehoboth irrigation schemes.',12.00,150,'default/onion.jpg','vegetable','available','2025-11-12 14:37:27'),
('e43a9a60-bf62-4987-9242-55fb3c2bccd3','04e49484-c554-491e-8b5c-9e2633af694a','Wheat','Durum wheat for bread-making, limited yield due to aridity.',200.00,40,'default/wheat.jpg','grain','available','2025-11-12 14:37:27'),
('8eaba99b-df38-4064-aa36-dee7aa6d1623','04e49484-c554-491e-8b5c-9e2633af694a','Cabbage','White cabbages, hardy in southern climates.',22.00,45,'default/cabbage.jpg','vegetable','available','2025-11-12 14:37:27'),
('0ee27e1a-7114-431d-bf7c-43fcf73e52f7','04e49484-c554-491e-8b5c-9e2633af694a','Lucerne (Alfalfa)','Green lucerne hay for livestock feed.',80.00,90,'default/lucerne.jpg','legume','available','2025-11-12 14:37:27');
 
DROP TABLE IF EXISTS orders CASCADE;

CREATE TABLE orders (
    order_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
    buyer_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    order_date TIMESTAMP NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'pending'
);

INSERT INTO orders (order_id, product_id, buyer_id, order_date, status)
VALUES
(uuid_generate_v4(),'099d03d8-79c1-4426-8052-0e65e9a70521','8089381d-495b-4202-a82a-1d2ca54a9185','2025-11-13','completed'),
(uuid_generate_v4(),'fb816ea6-30fc-415a-9d03-eab94ada9f9f','b9195d1e-d31e-4651-ba72-ae7ac86dee69','2025-11-14','pending'),
(uuid_generate_v4(),'22b1384e-41f8-4be6-b9b1-257d7327499b','3ff20f76-d9e8-42c6-817e-5d3e13c0048d','2025-11-12','completed');


 
DROP TABLE IF EXISTS market_trends CASCADE;

CREATE TABLE market_trends (
    trend_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
    demand_index INTEGER NOT NULL,
    avg_price NUMERIC(10,2) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW()
);

INSERT INTO market_trends (product_id, demand_index, avg_price, timestamp)
VALUES
('099d03d8-79c1-4426-8052-0e65e9a70521',85,118.00,'2025-11-13'),
('fb816ea6-30fc-415a-9d03-eab94ada9f9f',72,14.50,'2025-11-13'),
('22b1384e-41f8-4be6-b9b1-257d7327499b',60,98.00,'2025-11-13');
 
DROP TABLE IF EXISTS sms_logs CASCADE;

CREATE TABLE sms_logs (
    sms_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message_content TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    status VARCHAR(50) NOT NULL DEFAULT 'sent'
);
INSERT INTO sms_logs (user_id, message_content, timestamp, status)
VALUES
('8c325faa-e2f1-4c92-b48b-720f7199d8bb','Your product Mahangu has been successfully added to AgroConnect.','2025-11-12','sent'),
('05fa5925-c325-4e88-9143-5d522a9ccee6','Order #103 confirmed. Please prepare goods for collection.','2025-11-13','delivered'),
('8089381d-495b-4202-a82a-1d2ca54a9185','Thank you for your order! Your request is being processed.','2025-11-13','sent');
 
DROP TABLE IF EXISTS ratings CASCADE;

CREATE TABLE ratings (
    rating_id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    product_id UUID NOT NULL REFERENCES products(product_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
    rating_score INTEGER NOT NULL CHECK (rating_score BETWEEN 1 AND 5),
    comments TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);
INSERT INTO ratings (product_id, user_id, rating_score, comments, created_at)
VALUES
('fb816ea6-30fc-415a-9d03-eab94ada9f9f','b9195d1e-d31e-4651-ba72-ae7ac86dee69',5,'Fresh and juicy tomatoes, very good quality!','2025-11-13'),
('22b1384e-41f8-4be6-b9b1-257d7327499b','3ff20f76-d9e8-42c6-817e-5d3e13c0048d',4,'Good beans but packaging could improve.','2025-11-12'),
('099d03d8-79c1-4426-8052-0e65e9a70521','8089381d-495b-4202-a82a-1d2ca54a9185',5,'Mahangu was high quality and clean. Excellent!','2025-11-14');