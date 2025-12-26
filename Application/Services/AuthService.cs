using Application.DTOs.ApiResponseDTO;
using Application.DTOs.RequestDTOs.AuthDTO;
using Application.Interfaces.Service;
using Application.Interfaces.UnitOfwork;
using AutoMapper;
using Domain.Entities;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using System;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace Application.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IConfiguration _config;
        private readonly IEmailService _emailService;
        private readonly IRedisService _redisService;
        private readonly IJwtService _jwtService;
        private readonly IMapper _mapper;

        private record CachedRegister(string Otp, RegisterRequestDTO RegisterInfo);

        public AuthService(IUnitOfWork unitOfWork, IConfiguration config, IEmailService emailService, IRedisService redisService, IJwtService jwtService, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _config = config;
            _emailService = emailService;
            _redisService = redisService;
            _jwtService = jwtService;
            _mapper = mapper;
        }

        public async Task<ApiResponse> LoginAsync(LoginRequestDTO request)
        {
            var user = await _unitOfWork.UserRepository.FindAsync(u => u.Email == request.Email);

            if (user == null || string.IsNullOrEmpty(user.Password))
            {
                return new ApiResponse { IsSuccess = false, Message = "Sai email hoặc mật khẩu" };
            }

            if (user.Password.StartsWith("$2"))
            {
                var bcryptOk = BCrypt.Net.BCrypt.Verify(request.Password, user.Password);
                if (!bcryptOk)
                {
                    return new ApiResponse { IsSuccess = false, Message = "Sai email hoặc mật khẩu" };
                }

                var identityHasher = new PasswordHasher<User>();
                user.Password = identityHasher.HashPassword(user, request.Password);
                _unitOfWork.UserRepository.Update(user);
                await _unitOfWork.SaveChangesAsync();

                var tokenAfterBcrypt = _jwtService.GenerateToken(user);
                return new ApiResponse { IsSuccess = true, Message = "Đăng nhập thành công", Result = tokenAfterBcrypt };
            }

            var hasher = new PasswordHasher<User>();
            var verifyResult = hasher.VerifyHashedPassword(user, user.Password, request.Password);

            if (verifyResult == PasswordVerificationResult.Failed)
            {
                return new ApiResponse { IsSuccess = false, Message = "Sai email hoặc mật khẩu" };
            }

            if (verifyResult == PasswordVerificationResult.SuccessRehashNeeded)
            {
                user.Password = hasher.HashPassword(user, request.Password);
                _unitOfWork.UserRepository.Update(user);
                await _unitOfWork.SaveChangesAsync();
            }

            var token = _jwtService.GenerateToken(user);
            return new ApiResponse { IsSuccess = true, Message = "Đăng nhập thành công", Result = token };
        }

        public async Task<ApiResponse> RegisterAsync(RegisterRequestDTO request)
        {
            var existingUser = await _unitOfWork.UserRepository.FindAsync(u => u.Email == request.Email);
            if (existingUser != null) return new ApiResponse { IsSuccess = false, Message = "Email đã tồn tại" };

            if (request.Password != request.ConfirmPassword)
                return new ApiResponse { IsSuccess = false, Message = "Mật khẩu xác nhận không khớp" };

            var otp = new Random().Next(100000, 999999).ToString();

            var cacheData = new CachedRegister(otp, request);
            var json = JsonSerializer.Serialize(cacheData);
            await _redisService.StoreDataAsync(request.Email, json, TimeSpan.FromMinutes(5));

            await _emailService.SendEmailAsync(request.Email, "Mã xác thực đăng ký", $"<h1>OTP của bạn là: {otp}</h1>");

            return new ApiResponse { IsSuccess = true, Message = $"Đã gửi OTP đến {request.Email}" };
        }

        public async Task<ApiResponse> VerifyOtpAndCreateUserAsync(VerifyOtpRequestDTO request)
        {
            var json = await _redisService.GetValueAsync(request.Email);
            if (string.IsNullOrEmpty(json))
            {
                return new ApiResponse { IsSuccess = false, Message = "OTP đã hết hạn hoặc không tồn tại" };
            }

            CachedRegister data;
            try
            {
                data = JsonSerializer.Deserialize<CachedRegister>(json);
            }
            catch
            {
                return new ApiResponse { IsSuccess = false, Message = "Dữ liệu OTP bị lỗi" };
            }

            if (data == null || data.Otp != request.OtpCode)
            {
                return new ApiResponse { IsSuccess = false, Message = "Mã OTP không đúng" };
            }

            var regInfo = data.RegisterInfo;

            var newUser = new User
            {
                UserId = Guid.NewGuid(),
                Username = regInfo.UserName,
                Email = regInfo.Email,
                Password = string.Empty,
                IsActive = true,
                CreatedAt = DateTime.UtcNow
            };

            var hasher = new PasswordHasher<User>();
            newUser.Password = hasher.HashPassword(newUser, regInfo.Password);

            await _unitOfWork.UserRepository.CreateAsync(newUser);
            await _unitOfWork.SaveChangesAsync();

            await _redisService.DeleteDataAsync(request.Email);

            return new ApiResponse { IsSuccess = true, Message = "Đăng ký thành công" };
        }

        public async Task<ApiResponse> LoginGoogleAsync(GoogleLoginRequestDTO request)
        {
            try
            {
                var payload = await GoogleJsonWebSignature.ValidateAsync(request.IdToken);
                var user = await _unitOfWork.UserRepository.FindAsync(u => u.Email == payload.Email);
                var hasher = new PasswordHasher<User>();

                string generatedPassword = null;

                if (user == null)
                {
                    generatedPassword = GenerateSecurePassword(12);

                    user = new User
                    {
                        UserId = Guid.NewGuid(),
                        Username = payload.Name ?? payload.Email,
                        Email = payload.Email,
                        IsActive = true,
                        CreatedAt = DateTime.UtcNow
                    };

                    user.Password = hasher.HashPassword(user, generatedPassword);

                    await _unitOfWork.UserRepository.CreateAsync(user);
                    await _unitOfWork.SaveChangesAsync();
                }
                else if (string.IsNullOrEmpty(user.Password))
                {
                    generatedPassword = GenerateSecurePassword(12);
                    user.Password = hasher.HashPassword(user, generatedPassword);
                    _unitOfWork.UserRepository.Update(user);
                    await _unitOfWork.SaveChangesAsync();
                }

                if (!string.IsNullOrEmpty(generatedPassword))
                {
                    var emailBody = $@"
                        <p>Your account was created/updated via Google login.</p>
                        <p><strong>Email:</strong> {payload.Email}</p>
                        <p><strong>Password:</strong> {generatedPassword}</p>
                        <p>Please change your password after logging in.</p>";
                    await _emailService.SendEmailAsync(payload.Email, "Your account password", emailBody);
                }

                var token = _jwtService.GenerateToken(user);
                return new ApiResponse { IsSuccess = true, Message = "Login Google thành công", Result = token };
            }
            catch
            {
                return new ApiResponse { IsSuccess = false, Message = "Token Google không hợp lệ" };
            }
        }

        private static string GenerateSecurePassword(int length)
        {
            const string allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+";
            var chars = new char[length];
            for (int i = 0; i < length; i++)
            {
                int idx = RandomNumberGenerator.GetInt32(0, allowed.Length);
                chars[i] = allowed[idx];
            }
            return new string(chars);
        }
    }
}