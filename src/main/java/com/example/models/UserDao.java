package com.example.models;

import org.springframework.data.repository.CrudRepository;

import javax.transaction.Transactional;
import java.util.List;

/**
 * Created by Rinat on 14/04/2017.
 */
@Transactional
public interface UserDao extends CrudRepository<User, Long> {

    public List<User> findAll();

}
