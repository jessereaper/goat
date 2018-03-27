# frozen_string_literal: true
class WorkInfo < ApplicationRecord
  belongs_to :user
  has_one :key_management, foreign_key: :user_id, primary_key: :user_id, dependent: :destroy
  before_save :encrypt_ssn

  # We should probably use this
  def last_four
    "***-**-" << self.decrypt_ssn[-4, 4]
  end

  def encrypt_ssn
   aes = OpenSSL::Cipher::Cipher.new(cipher_type)
   aes.encrypt
   aes.key = key
   aes.iv = iv if iv != nil
   self.encrypted_ssn = aes.update(self.SSN) + aes.final
   self.SSN = nil
  end

  def decrypt_ssn
     aes = OpenSSL::Cipher::Cipher.new(cipher_type)
     aes.decrypt
     aes.key = key
     aes.iv = iv if iv != nil
     aes.update(self.encrypted_ssn) + aes.final
  end

  def key
    raise "Key Missing" if !(KEY)
    KEY
  end

  def iv
    raise "No IV for this User" if !(self.key_management.iv)
    self.key_management.iv
  end

  def cipher_type
    'aes-256-cbc'
  end

  #work_info.each do |wi|
   list = [:user_id, :SSN]
   info = WorkInfo.new(wi.reject {|k| list.include?(k)})
   info.user_id = wi[:user_id]
   info.build_key_management({:user_id => wi[:user_id], :iv => SecureRandom.hex(32) })
   info.SSN = wi[:SSN]
   info.save
  end
