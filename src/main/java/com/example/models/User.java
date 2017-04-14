package com.example.models;
import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.Date;

/**
 * Created by Rinat on 14/04/2017.
 */

@Entity
@Table(name = "users")
public class User {


    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @NotNull
    private String name;

    @NotNull
    private Date date;

    public User() { }

    public User(long id) {
        this.id = id;
    }

    public User(String name, Date date) {
        this.name = name;
        this.date = date;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Date getDate() {
        return date;
    }

    public void setDate(Date date) {
        this.date = date;
    }
}
