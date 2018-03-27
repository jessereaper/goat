class AddPassswordHashAndSaltToUsers < ActiveRecord::Migration[5.1]
  def change
    add_column :users, :password_hash, :text
    add_column :users, :password_salt, :text
  end
end
