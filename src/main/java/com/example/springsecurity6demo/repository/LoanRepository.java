package com.example.springsecurity6demo.repository;


import com.example.springsecurity6demo.domain.Loans;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface LoanRepository extends JpaRepository<Loans, Long> {
	
	List<Loans> findByCustomerIdOrderByStartDtDesc(int customerId);

}
