using Application.DTOs.RequestDTOs;
using Application.DTOs.ResponseDTOs;
using Application.Interfaces.Service;
using Application.Interfaces.UnitOfwork;
using AutoMapper;
using Domain.Entities;
using Microsoft.AspNetCore.Identity;

namespace Application.Services
{
    public class UserService : IUserService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public UserService(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }
          

        /// <summary>
        /// Create User   
        /// </summary>
        public async Task CreateAsync(CreateUserDTOs requestDTO)
        {
            var entity = _mapper.Map<User>(requestDTO);

            entity.UserId = Guid.NewGuid();
            entity.IsActive = true;
            entity.CreatedAt = DateTime.UtcNow;

            if (!string.IsNullOrEmpty(requestDTO.Password))
            {
                var hasher = new PasswordHasher<User>();
                entity.Password = hasher.HashPassword(entity, requestDTO.Password);
            }

            //Reflect to DB
            await _unitOfWork.UserRepository.CreateAsync(entity);
            await _unitOfWork.SaveChangesAsync();
        }

        /// <summary>
        /// Delete User
        /// </summary>
        public async Task DeleteAsync(Guid id)
        {
            var post = await _unitOfWork.UserRepository.GetByIdAsync(id);
            if (post != null)
            {
                post.IsActive = false;
                post.UpdatedAt = DateTime.UtcNow;

                //Logical deletion
                await _unitOfWork.SaveChangesAsync();
            }
        }

        /// <summary>
        /// Get All Users
        /// </summary>
        public async Task<IEnumerable<UserResponseDTO>> GetAllAsync()
        {
            var users = await _unitOfWork.UserRepository.GetAllAsync();
            var activeUsers = users.Where(p => p.IsActive == true).ToList();
            return _mapper.Map<IEnumerable<UserResponseDTO>>(activeUsers);
        }

        /// <summary>
        /// Get User By ID
        /// </summary>
        public async Task<UserResponseDTO> GetById(Guid id)
        {
            var user = await _unitOfWork.UserRepository.GetByIdAsync(id);
            if (user == null || user.IsActive == false)
            {
                return null;
            }
            return _mapper.Map<UserResponseDTO>(user);
        }

        /// <summary>
        /// Update User
        /// </summary>
        public async Task UpdateAsync(UpdateUserDTO requestDTO)
        {
            var userInDb = await _unitOfWork.UserRepository.GetByIdAsync(requestDTO.UserId);

            if (userInDb != null)
            {
                _mapper.Map(requestDTO, userInDb);
                userInDb.UpdatedAt = DateTime.UtcNow;

                //Reflect to DB
                _unitOfWork.UserRepository.Update(userInDb);
                await _unitOfWork.SaveChangesAsync();
            }
        }
    }
}
