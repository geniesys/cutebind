CREATE DATABASE IF NOT EXISTS `cuteresolve` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `cuteresolve`;

CREATE TABLE IF NOT EXISTS `peers` (
  `peer_id` varchar(40) NOT NULL,
  `external_ip` int(11) NOT NULL,
  `internal_ip` int(11) NOT NULL,
  `ctime` int(11) NOT NULL,
  PRIMARY KEY (`peer_id`),
  KEY `external_ip` (`external_ip`,`internal_ip`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `dnsbl_blacklist` (
  `ip` varchar(15) NOT NULL,
  `date_added` datetime DEFAULT CURRENT_TIMESTAMP,
  `date_expires` datetime DEFAULT NULL,
  `source` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`ip`),
  KEY `ix_date_added` (`date_added`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `dnsbl_whitelist` (
  `ip` varchar(15) NOT NULL,
  `date_added` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `date_expires` datetime DEFAULT NULL COMMENT 'Record expires and will be removed after this date. Optional. Leave NULL for no exiration.',
  `notes` varchar(255) DEFAULT NULL COMMENT 'A note to indicate reason why this IP is whitelisted.',
  PRIMARY KEY (`ip`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COMMENT='Mail will always be accepted from these IP addresses.';

CREATE TABLE IF NOT EXISTS `domains` (
  `domain` varchar(45) NOT NULL COMMENT 'Domain name such as example.com',
  `date_registered` datetime NOT NULL COMMENT 'Date of domain registration.',
  `date_added` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`domain`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COMMENT='Provides long-term storage for domain-related information.';

CREATE TABLE IF NOT EXISTS `surbl_blacklist` (
  `url` varchar(45) NOT NULL,
  `date_added` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `date_expires` datetime DEFAULT NULL,
  `notes` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`url`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `surbl_whitelist` (
  `url` varchar(45) NOT NULL,
  `date_added` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `notes` varchar(80) DEFAULT NULL,
  PRIMARY KEY (`url`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE TABLE IF NOT EXISTS `surbl_kb` (
  `domain` varchar(45) NOT NULL,
  `date_seen` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`domain`,`date_seen`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_ip_blacklist` AS select distinct substring_index(`spam`.`received_from_ip`,':',1) AS `ip`,now() AS `date_added`,`spam`.`source` AS `source` from `spam` where (`spam`.`received_from_ip` is not null);
CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_spam_summary_by_from_addr` AS select `spam`.`from_addr` AS `from_addr`,count(0) AS `occurances` from `spam` where ((`spam`.`from_addr` is not null) and (`spam`.`from_addr` <> '')) group by 1 order by `occurances` desc;
CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_spam_summary_by_from_domain` AS select substring_index(`spam`.`from_addr`,'@',-(1)) AS `from_domain`,count(0) AS `occurances` from `spam` where ((`spam`.`from_addr` is not null) and (`spam`.`from_addr` <> '')) group by 1 order by `occurances` desc;
CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_spam_summary_by_from_name` AS select `spam`.`from_name` AS `from_name`,count(0) AS `occurances` from `spam` where ((`spam`.`from_name` is not null) and (`spam`.`from_name` <> '')) group by 1 order by `occurances` desc;
CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_spam_summary_by_ip` AS select substring_index(`spam`.`received_from_ip`,':',1) AS `ip`,count(0) AS `occurances` from `spam` where (`spam`.`received_from_ip` is not null) group by 1 order by `occurances` desc;
CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_spam_summary_by_subject` AS select `spam`.`subject` AS `subject`,count(0) AS `occurances` from `spam` where ((`spam`.`subject` is not null) and (`spam`.`subject` <> '')) group by 1 order by `occurances` desc;
CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `v_spam_summary_by_subnet` AS select concat(substring_index(`spam`.`received_from_ip`,'.',3),'.*') AS `ip`,count(distinct `spam`.`received_from_ip`) AS `unique_ip_count`,count(0) AS `total_ip_count`,(`dnsbl_blacklist`.`ip` is not null) AS `in_blacklist` from (`spam` left join `dnsbl_blacklist` on((`dnsbl_blacklist`.`ip` = concat(substring_index(`spam`.`received_from_ip`,'.',3),'.*')))) group by substring_index(`spam`.`received_from_ip`,'.',3) order by `total_ip_count` desc;

DELIMITER $$
CREATE DEFINER=`root`@`localhost` PROCEDURE `HOURLY`()
    COMMENT 'Primary purpose of this procedure is to update blacklist from collected spam records.\n    The name HOURLY only suggests execution frequency. On high traffic systems recommended frequency is every 15, 10 or even 5 minutes.\n    This process should be somewhat syncronized with junkmail collection activity. Idealy, it should run shortly after it.'
BEGIN

/* Delete expired records from whitelist table */
DELETE FROM dnsbl_whitelist WHERE date_expires IS NOT NULL AND date_expires < NOW();

/* Delete expired records from blacklist table */
DELETE FROM dnsbl_blacklist WHERE date_expires IS NOT NULL AND date_expires < NOW();

/* Delete old records from spam table */
DELETE FROM spam WHERE COALESCE(date_received, date_sent) < DATE_ADD(NOW(), INTERVAL -30 DAY);

/* Delete records from spam table where IP is whitelisted */
DELETE FROM spam WHERE `received_from_ip` IN (SELECT `ip` FROM dnsbl_whitelist);

/* The following statement helps with "unsafe statement" warning in replication environment. */
SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;
#SET SESSION binlog_format='ROW';

/* Append new records to blacklist table. Lock period is 30 days. */
REPLACE INTO dnsbl_blacklist (`ip`,`date_added`,`source`,`date_expires`)
SELECT	DISTINCT T1.*, DATE_ADD(NOW(), INTERVAL 30 DAY) as `date_expires`
  FROM	v_ip_blacklist	T1
		LEFT JOIN
		dnsbl_blacklist	T2 ON T2.ip IN (T1.ip, CONCAT(SUBSTRING_INDEX(T1.`ip`,'.',3),'.*'))
  WHERE	T2.ip IS NULL;

/* When 5 or more unique IP's in the same class C subnet are found, consolidate it into a single wildcard rule. Lock period is 180 days. */
# Warning 1592: Unsafe statement written to the binary log using statement format since BINLOG_FORMAT = STATEMENT. REPLACE... SELECT is unsafe because the order in which rows are retrieved by the SELECT determines which (if any) rows are replaced. This order cannot be predicted and may differ on master and the slave.
REPLACE INTO dnsbl_blacklist (`ip`, `date_added`, `source`,`date_expires`)
 SELECT	T1.`ip`,
		NOW() as `date_added`,
		'Class_C consolidated subnet. 5 or more occurances. Created by HOURLY SP.' as `source`,
        DATE_ADD(NOW(), INTERVAL 180 DAY) as `date_expires`
 FROM (
 		SELECT CONCAT(SUBSTRING_INDEX(`ip`,'.',3),'.*') as `ip`, Count(*) as occurances
		  FROM dnsbl_blacklist
		 GROUP BY SUBSTRING_INDEX(`ip`,'.',3)
		 ORDER BY occurances DESC
/*
		SELECT CONCAT(class_c,'.*') as `ip`, Count(*) as occurances
		  FROM (SELECT SUBSTRING_INDEX(`ip`,'.',3) as class_c FROM dnsbl_blacklist GROUP BY `ip`) as T1
		 GROUP BY class_c
		 ORDER BY occurances DESC
*/
     ) T1
	 LEFT JOIN
     dnsbl_blacklist T2	ON T2.`ip` = T1.`ip`
WHERE T1.occurances >= 5
  AND T2.`ip` IS NULL;

/* ... and remove individual IP's that we used above to build the wildcard rules. (has to be done through temporary table) */
CREATE TEMPORARY TABLE `temp` ENGINE=Memory (
		SELECT SUBSTRING_INDEX(`ip`,'.',3) as class_c
          FROM dnsbl_blacklist
         WHERE RIGHT(`ip`,1) = '*'
);
# SELECT * FROM `temp`;

DELETE FROM cuteresolve.dnsbl_blacklist
# SELECT * FROM cuteresolve.blacklist
 WHERE SUBSTRING_INDEX(`ip`,'.',3) IN (SELECT class_c FROM `temp`)
   AND RIGHT(`ip`,1) != '*';

DROP TABLE `temp`;
/* --- End --- */

/* Remove [SPAM] prefix in Subject. This is temporary. It should be done in mailRetriever.php using preg_replace() */
UPDATE cuteresolve.spam SET `subject` = REPLACE(`subject`,'[SPAM] ','') WHERE `subject` LIKE '[SPAM] %';

END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`root`@`localhost` PROCEDURE `HOUSEKEEPING`()
    COMMENT 'Database maintenance task. This set of queries is intended to run once a day. It is not necessary to run it more frequently.'
BEGIN

/* Delete old records from domains table */
DELETE FROM domains WHERE date_added < DATE_ADD(NOW(), INTERVAL -1 YEAR);

END$$
DELIMITER ;

DELIMITER $$
CREATE DEFINER=`root`@`localhost` PROCEDURE `shedule_events`()
BEGIN
/*
CREATE DEFINER = `root`@`localhost`
 EVENT IF NOT EXISTS EVERY_30_MINUTES
    ON SCHEDULE EVERY 30 MINUTE STARTS '2015-01-01 00:01:00'
    COMMENT 'Shedules what needs to run every 30 minutes. Read instructions for every procedure being executed here.'
    DO
      CALL HOURLY;

CREATE DEFINER = `root`@`localhost`
 EVENT IF NOT EXISTS DAILY
    ON SCHEDULE EVERY 1 DAY STARTS '2015-01-01 00:10:00'
    COMMENT 'Shedules what needs to run once a day. Read instructions for every procedure being executed here.'
    DO
      CALL HOUSEKEEPING;
*/
END$$
DELIMITER ;


# Create the user if it doesn't exist and grant priviledges
GRANT SELECT,INSERT,UPDATE,DELETE,EXECUTE,SHOW VIEW,CREATE TEMPORARY TABLES,LOCK TABLES ON `cuteresolve`.* to 'cutebind'@'%' identified by 'password';
FLUSH PRIVILEGES;
