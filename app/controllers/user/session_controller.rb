# -*- encoding : utf-8 -*-
class User::SessionController < UserController

  before_filter :work_out_post_redirect, :only => [ :new, :create ]
  before_filter :set_request_from_foreign_country, :only => [ :new, :create ]

  def new
    render :template => 'user/sign'
  end

  def create
    if @post_redirect.present?
      @user_signin =
        User.authenticate_from_form(user_signin_params,
                                    @post_redirect.reason_params[:user_name])
    end
    if @post_redirect.nil? || @user_signin.errors.size > 0
      # Failed to authenticate
      render :template => 'user/sign'
    else
      # Successful login
      if @user_signin.email_confirmed
        session[:user_id] = @user_signin.id
        session[:ttl] = nil
        session[:user_circumstance] = nil
        session[:remember_me] = params[:remember_me] ? true : false

        if is_modal_dialog
          render :template => 'show'
        else
          do_post_redirect @post_redirect, @user_signin, :signin
        end
      else
        send_confirmation_mail @user_signin
      end
    end
  end

  def destroy
    clear_session_credentials
    if params[:r]
      redirect_to URI.parse(params[:r]).path
    else
      redirect_to frontpage_path
    end
  end

  def confirm
    post_redirect = PostRedirect.find_by_email_token(params[:email_token])

    if post_redirect.nil?
      render :template => 'user/bad_token'
      return
    end

    case post_redirect.circumstance
    when 'login_as'
      @user = confirm_user!(post_redirect.user)
      session[:user_id] = @user.id
    when 'change_password'
      unless session[:user_id] == post_redirect.user_id
        clear_session_credentials
      end

      session[:change_password_post_redirect_id] = post_redirect.id
    when 'normal', 'change_email'
      # !User.stay_logged_in_on_redirect?(nil)
      # # => true
      # !User.stay_logged_in_on_redirect?(user)
      # # => true
      # !User.stay_logged_in_on_redirect?(admin)
      # # => false
      if User.stay_logged_in_on_redirect?(@user)
        session[:admin_confirmation] = 1
      else
        @user = confirm_user!(post_redirect.user)
      end

      session[:user_id] = @user.id
    end

    session[:user_circumstance] = post_redirect.circumstance
    do_post_redirect post_redirect, @user, :confirm
  end

  private

  def user_signin_params
    params.require(:user_signin).permit(:email, :password)
  end

end
