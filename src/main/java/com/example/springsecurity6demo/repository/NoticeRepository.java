package com.example.springsecurity6demo.repository;


import com.example.springsecurity6demo.domain.Notice;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;

@Repository
public interface NoticeRepository extends JpaRepository<Notice, Long> {
	
	@Query(value = "from Notice n where CURDATE() BETWEEN n.noticBegDt AND n.noticEndDt")
	List<Notice> findAllActiveNotices();

}
