package com.example.springsecurity6demo.repository;

import com.example.springsecurity6demo.domain.Contact;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ContactRepository extends JpaRepository<Contact, Long> {
	
	
}
