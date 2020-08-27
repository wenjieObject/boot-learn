package com.wenjie.esblog.pojo;

import lombok.Data;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.Table;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Size;

@Data
@Entity
@Table(name = "user_t")
public class User implements Serializable {
	private static final long serialVersionUID = -3320971805590503443L;
	@Id
	@GeneratedValue
	@NotNull(message = "用户id不能为空")
	private long id;

	@NotNull(message = "用户账号不能为空")
	@Size(min = 6, max = 11, message = "账号长度必须是6-11个字符")
	private String username;

	@NotNull(message = "用户密码不能为空")
	@Size(min = 6, max = 11, message = "密码长度必须是6-16个字符")
	private String password;

	private String salt;

	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "user_role_t", joinColumns = { @JoinColumn(name = "uid") }, inverseJoinColumns = {
			@JoinColumn(name = "rid") })
	private List<SysRole> roles;

	public long getId() {
		return id;
	}

	public void setId(long id) {
		this.id = id;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSalt() {
		return salt;
	}

	public void setSalt(String salt) {
		this.salt = salt;
	}

	public List<SysRole> getRoles() {
		return roles;
	}

	public void setRoles(List<SysRole> roles) {
		this.roles = roles;
	}

	public String getCredentialsSalt() {
		return username + salt + salt;
	}

	@Override
	public String toString() {
		return "User [id=" + id + ", username=" + username + "]";
	}

}

