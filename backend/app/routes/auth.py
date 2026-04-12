"""
Auth Routes — Register, Login, Profile
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)
from app import db, bcrypt
from app.models import User

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    """Register akun baru."""
    data = request.get_json() or {}

    # Validasi input
    required = ["email", "username", "password"]
    for field in required:
        if not data.get(field, "").strip():
            return jsonify({"error": f"Field '{field}' wajib diisi"}), 400

    email    = data["email"].strip().lower()
    username = data["username"].strip()
    password = data["password"]
    fullname = data.get("full_name", "").strip()

    # Validasi format
    if len(password) < 8:
        return jsonify({"error": "Password minimal 8 karakter"}), 400
    if "@" not in email:
        return jsonify({"error": "Format email tidak valid"}), 400
    if len(username) < 3:
        return jsonify({"error": "Username minimal 3 karakter"}), 400

    # Cek duplikat
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email sudah terdaftar"}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username sudah digunakan"}), 409

    # Buat user baru
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    user = User(
        email=email,
        username=username,
        password=hashed_pw,
        full_name=fullname,
        role="user",
    )
    db.session.add(user)
    db.session.commit()

    # Generate tokens
    access_token  = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify({
        "message":      "Registrasi berhasil",
        "user":         user.to_dict(),
        "access_token": access_token,
        "refresh_token":refresh_token,
    }), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    """Login dengan email/username + password."""
    data = request.get_json() or {}
    identifier = data.get("email", data.get("username", "")).strip()
    password   = data.get("password", "")

    if not identifier or not password:
        return jsonify({"error": "Email/username dan password wajib diisi"}), 400

    # Cari user by email atau username
    user = (User.query.filter_by(email=identifier.lower()).first() or
            User.query.filter_by(username=identifier).first())

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Email/username atau password salah"}), 401

    if not user.is_active:
        return jsonify({"error": "Akun dinonaktifkan. Hubungi administrator."}), 403

    access_token  = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify({
        "message":       "Login berhasil",
        "user":          user.to_dict(),
        "access_token":  access_token,
        "refresh_token": refresh_token,
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token."""
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=user_id)
    return jsonify({"access_token": access_token}), 200


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
    """Ambil profil user yang sedang login."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User tidak ditemukan"}), 404
    return jsonify({"user": user.to_dict()}), 200


@auth_bp.route("/profile", methods=["PUT"])
@jwt_required()
def update_profile():
    """Update profil user."""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User tidak ditemukan"}), 404

    data = request.get_json() or {}

    if "full_name" in data:
        user.full_name = data["full_name"].strip()

    if "password" in data:
        new_pw = data["password"]
        if len(new_pw) < 8:
            return jsonify({"error": "Password minimal 8 karakter"}), 400
        # Verifikasi password lama
        old_pw = data.get("old_password", "")
        if not bcrypt.check_password_hash(user.password, old_pw):
            return jsonify({"error": "Password lama tidak sesuai"}), 401
        user.password = bcrypt.generate_password_hash(new_pw).decode("utf-8")

    db.session.commit()
    return jsonify({"message": "Profil berhasil diperbarui", "user": user.to_dict()}), 200
