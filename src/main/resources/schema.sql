CREATE TABLE IF NOT EXISTS `USER_INFO` (
                                           `ID` BIGINT AUTO_INCREMENT PRIMARY KEY,
                                           `USER_NAME` VARCHAR(100) NOT NULL,
                                           `PASSWORD` VARCHAR(100) NOT NULL,
                                           `EMAIL_ID` VARCHAR(200) NOT NULL,
                                           `MOBILE_NUMBER` VARCHAR(20),
                                           `ROLES` VARCHAR(100) NOT NULL
);

-- CREATE TABLE IF NOT EXISTS `REFRESH_TOKENS` (
--                                                 `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
--                                                 `REFRESH_TOKEN` VARCHAR(10000) NOT NULL,
--                                                 `REVOKED` BOOLEAN,
--                                                 `user_id` BIGINT,
--                                                 FOREIGN KEY (`user_id`) REFERENCES `USER_INFO`(`id`)
-- );