# -*- encoding : utf-8 -*-
class AlaveteliPro::PaymentMethodsController < AlaveteliPro::BaseController
  before_filter :authenticate

  def update
    @token = Stripe::Token.retrieve(params[:stripeToken])
    @old_card_id = params[:old_card_id]
    @customer = Stripe::Customer.
                  retrieve(current_user.pro_account.stripe_customer_id)

    @customer.sources.create(source: @token.id)
    @customer.sources.retrieve(@old_card_id).delete
    flash[:notice] = _('Your payment details have been updated')

    redirect_to account_path
  end

  private

  def authenticate
    post_redirect_params = {
      :web => _('To update your payment details'),
      :email => _('To update your payment details'),
      :email_subject => _('To update your payment details') }
    authenticated?(post_redirect_params)
  end

end
