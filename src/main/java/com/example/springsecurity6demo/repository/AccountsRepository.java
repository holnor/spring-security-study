package com.example.springsecurity6demo.repository;

import com.example.springsecurity6demo.domain.Accounts;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountsRepository extends JpaRepository<Accounts, Long> {
	
	Accounts findByCustomerId(int customerId);

}
