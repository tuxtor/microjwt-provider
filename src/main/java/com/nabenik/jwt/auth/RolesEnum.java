package com.nabenik.jwt.auth;

public enum RolesEnum {
	WEB("web"),
	MOBILE("mobile");

	private String role;

	public String getRole() {
		return this.role;
	}

	RolesEnum(String role) {
		this.role = role;
	}
}
